use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::Algorithm;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::error::{Error, Result};
use crate::group::GroupManager;
use crate::password::PasswordPolicy;
use crate::relay::RelayBackend;
use crate::service_client::ServiceClientManager;
use crate::token::TokenManager;
use crate::user::{User, UserManager};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The authenticated caller behind a token, resolved backend-agnostically by
/// [`Database::resolve_principal`]: either a human [`User`] or a scoped
/// machine-to-machine service client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    User(User),
    Service {
        client_id: String,
        scopes: Vec<String>,
    },
}

#[derive(Clone)]
pub struct Database {
    pub(crate) backend: Arc<Backend>,
}

pub(crate) enum Backend {
    Local(LocalBackend),
    Relay(RelayBackend),
}

pub(crate) struct LocalBackend {
    pub pool: SqlitePool,
    pub token_manager: Option<TokenManager>,
    pub password_policy: PasswordPolicy,
    /// このデータベース(=発行元サーバー)を一意に識別する UUID。初回オープン時に
    /// 生成され `meta` テーブルに永続化される。JWT の `iss` クレームとして使う。
    pub server_id: String,
}

impl LocalBackend {
    /// `token` が `Some` のときに JWT を検証する。`TokenManager` が未設定の場合は
    /// `Error::MissingTokenManager` を返す。`None` の場合は何もせず `Ok(())`。
    pub(crate) fn verify_if_present(&self, token: Option<&str>) -> Result<()> {
        if let Some(t) = token {
            let tm = self
                .token_manager
                .as_ref()
                .ok_or(Error::MissingTokenManager)?;
            tm.verify_token(t)?;
        }
        Ok(())
    }
}

impl Database {
    /// Open a backend from a single target string, dispatching on its form:
    ///
    /// - looks like a URL (contains `://`) → relay backend. The scheme must be
    ///   `http` or `https`, otherwise [`Error::InvalidArgument`] is returned
    ///   (this guards against a mistyped URL silently becoming a file path).
    ///   Passing a `secret` with a relay target is rejected, since the central
    ///   server holds the signing key.
    /// - anything else → local SQLite file at that path, with `secret` used as
    ///   the JWT secret path (or `None` for no token manager).
    ///
    /// [`open_local`](Self::open_local) / [`open_relay`](Self::open_relay) remain
    /// available when the backend is known up front.
    pub async fn open(target: &str, secret: Option<&str>) -> Result<Self> {
        if target.contains("://") {
            let url = url::Url::parse(target)?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(Error::InvalidArgument(format!(
                    "unsupported URL scheme '{}': relay backend requires http or https",
                    url.scheme()
                )));
            }
            if secret.is_some() {
                return Err(Error::InvalidArgument(
                    "secret is not applicable to a relay (URL) backend".into(),
                ));
            }
            Self::open_relay(target)
        } else {
            Self::open_local(target, secret).await
        }
    }

    /// Open a local SQLite database. If `secret_path` is provided, a `TokenManager` is
    /// initialised from that file (created if missing); otherwise calling
    /// `token_manager()` returns `Error::MissingTokenManager`.
    ///
    /// Uses the default [`PasswordPolicy`] (minimum
    /// [`MIN_PASSWORD_LEN`](crate::MIN_PASSWORD_LEN) characters); use
    /// [`open_local_with_policy`](Self::open_local_with_policy) to configure it.
    pub async fn open_local(
        db_path: impl AsRef<Path>,
        secret_path: Option<impl AsRef<Path>>,
    ) -> Result<Self> {
        Self::open_local_with_policy(db_path, secret_path, PasswordPolicy::default()).await
    }

    /// Like [`open_local`](Self::open_local), but with an explicit
    /// [`PasswordPolicy`] (e.g. a custom minimum length) applied to every
    /// password set through this `Database` (create / update / login-adjacent
    /// paths that hash a new password).
    pub async fn open_local_with_policy(
        db_path: impl AsRef<Path>,
        secret_path: Option<impl AsRef<Path>>,
        password_policy: PasswordPolicy,
    ) -> Result<Self> {
        let path = db_path.as_ref();
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;

        run_migrations(&pool, path).await?;

        let server_id = load_or_create_server_id(&pool).await?;

        let token_manager = match secret_path {
            Some(p) => {
                Some(TokenManager::from_file(p, Algorithm::HS256)?.with_issuer(&server_id))
            }
            None => None,
        };

        Ok(Self {
            backend: Arc::new(Backend::Local(LocalBackend {
                pool,
                token_manager,
                password_policy,
                server_id,
            })),
        })
    }

    /// Open an HTTP relay backend pointing at a remote UserPermission server.
    pub fn open_relay(url: impl AsRef<str>) -> Result<Self> {
        let backend = RelayBackend::new(url.as_ref())?;
        Ok(Self {
            backend: Arc::new(Backend::Relay(backend)),
        })
    }

    /// [`open_relay`](Self::open_relay) と同様だが、接続先サーバーの
    /// server_id を事前に pin する。ログインや introspect の応答に含まれる
    /// server_id が一致しない場合(=リレー先を別サーバーに切り替えた場合)、
    /// 内部トークンを破棄して [`Error::RelayServerMismatch`] を返す。
    ///
    /// クライアントアプリは初回接続時に [`server_id`](Self::server_id) で取得した
    /// 値を永続化し、次回以降この関数に渡すことで「同じ URL でも中身が別サーバー
    /// に変わった」「別サーバーの同名ユーザーに誤ってログインした」事故を防げる。
    pub fn open_relay_pinned(url: impl AsRef<str>, expected_server_id: &str) -> Result<Self> {
        let backend = RelayBackend::new(url.as_ref())?;
        backend.pin_server_id(expected_server_id);
        Ok(Self {
            backend: Arc::new(Backend::Relay(backend)),
        })
    }

    /// No-op for local backends (the pool is already connected). For relay backends,
    /// this would lazily warm the HTTP client (currently nothing).
    pub async fn connect(&self) -> Result<()> {
        Ok(())
    }

    /// Close the underlying pool / client.
    pub async fn close(&self) -> Result<()> {
        match &*self.backend {
            Backend::Local(local) => local.pool.close().await,
            Backend::Relay(_) => {}
        }
        Ok(())
    }

    pub fn users(&self) -> UserManager {
        UserManager::new(self.backend.clone())
    }

    pub fn groups(&self) -> GroupManager {
        GroupManager::new(self.backend.clone())
    }

    pub fn service_clients(&self) -> ServiceClientManager {
        ServiceClientManager::new(self.backend.clone())
    }

    /// Log in with a username and password, returning a freshly issued access
    /// token (or `None` if the credentials are rejected).
    ///
    /// - local: verifies the password and signs a JWT. `expires_in` sets the
    ///   token lifetime.
    /// - relay: delegates to the central server's `POST /token` and stores the
    ///   returned token internally for subsequent requests. `expires_in` is
    ///   ignored — the server owns the token lifetime.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        expires_in: Duration,
    ) -> Result<Option<String>> {
        self.users().login(username, password, expires_in).await
    }

    /// Log in as a machine-to-machine service via the client-credentials grant,
    /// returning a short-lived scoped access token (or `None` if the client is
    /// unknown, inactive, expired, or the secret does not match).
    ///
    /// - local: verifies the secret and signs a scoped JWT. `expires_in` sets
    ///   the token lifetime.
    /// - relay: delegates to the central server's `POST /token` and stores the
    ///   token (plus the credentials, for transparent refresh on a 401)
    ///   internally. `expires_in` is ignored — the server owns the lifetime.
    pub async fn login_service(
        &self,
        client_id: &str,
        client_secret: &str,
        expires_in: Duration,
    ) -> Result<Option<String>> {
        self.service_clients()
            .login(client_id, client_secret, expires_in)
            .await
    }

    /// Convenience wrapper around [`resolve_principal`](Self::resolve_principal)
    /// that returns the [`User`] only when the token belongs to an active user,
    /// discarding service tokens and invalid/expired tokens as `Ok(None)`.
    pub async fn verify_token_and_get_user(&self, token: &str) -> Result<Option<User>> {
        match self.resolve_principal(token).await? {
            Some(Principal::User(user)) => Ok(Some(user)),
            _ => Ok(None),
        }
    }

    /// Resolve a bearer token to its [`Principal`] (user or service client),
    /// backend-agnostically.
    ///
    /// - local: verifies the JWT with the configured [`TokenManager`], then
    ///   classifies the token by its `kind` claim — a `service` token yields
    ///   [`Principal::Service`], otherwise the `sub` user is loaded and
    ///   returned as [`Principal::User`].
    /// - relay: delegates to the server via `POST /introspect`, which performs
    ///   the same classification server-side.
    ///
    /// Returns `Ok(None)` for an invalid, expired, or inactive-user token in
    /// both cases. Local without a token manager yields
    /// [`Error::MissingTokenManager`].
    pub async fn resolve_principal(&self, token: &str) -> Result<Option<Principal>> {
        match &*self.backend {
            Backend::Local(local) => {
                let tm = local
                    .token_manager
                    .as_ref()
                    .ok_or(Error::MissingTokenManager)?;
                let claims = match tm.verify_token(token) {
                    Ok(c) => c,
                    Err(_) => return Ok(None),
                };
                if claims.get("kind").and_then(Value::as_str) == Some("service") {
                    let client_id = claims
                        .get("client_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let scopes = claims
                        .get("scope")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .split_whitespace()
                        .map(str::to_string)
                        .collect();
                    return Ok(Some(Principal::Service { client_id, scopes }));
                }
                let user_id = claims
                    .get("sub")
                    .and_then(Value::as_str)
                    .and_then(|s| uuid::Uuid::parse_str(s).ok());
                let Some(id) = user_id else {
                    return Ok(None);
                };
                // Reject tokens minted before the user's last revocation: the
                // `ver` claim must match the current `token_version` (tokens
                // predating the column carry no `ver` and count as version 0).
                let token_ver = claims.get("ver").and_then(Value::as_i64).unwrap_or(0);
                let current_ver: Option<i64> =
                    sqlx::query_scalar("SELECT token_version FROM users WHERE id = ?")
                        .bind(id.to_string())
                        .fetch_optional(&local.pool)
                        .await?;
                if current_ver != Some(token_ver) {
                    return Ok(None);
                }
                match self.users().get_by_id(id, None).await? {
                    Some(user) if user.is_active => Ok(Some(Principal::User(user))),
                    _ => Ok(None),
                }
            }
            Backend::Relay(relay) => relay.introspect(token).await,
        }
    }

    /// Revoke every token previously issued to `user_id` by bumping the user's
    /// `token_version`; see [`UserManager::revoke_tokens`].
    pub async fn revoke_tokens(&self, user_id: uuid::Uuid) -> Result<bool> {
        self.users().revoke_tokens(user_id, None).await
    }

    /// このデータベースの発行元サーバー識別子 (server_id) を返す。
    ///
    /// - local: `meta` テーブルに永続化された UUID(初回オープン時に生成)。
    /// - relay: サーバーの `GET /server-info` から取得し、以後の応答と照合する
    ///   ために pin する。既に pin 済みなら追加リクエストなしでその値を返す。
    pub async fn server_id(&self) -> Result<String> {
        match &*self.backend {
            Backend::Local(local) => Ok(local.server_id.clone()),
            Backend::Relay(relay) => relay.fetch_server_id().await,
        }
    }

    /// Ensure an admin user exists (local backend only).
    ///
    /// If any admin already exists, this is a no-op returning `Ok(None)`.
    /// Otherwise the named user is created if missing, then promoted to admin,
    /// and returned as `Ok(Some(user))`. For relay backends this always returns
    /// `Ok(None)`: the central server owns admin provisioning, so a client must
    /// never bootstrap one.
    pub async fn bootstrap_admin_if_needed(
        &self,
        username: &str,
        password: &str,
        display_name: &str,
    ) -> Result<Option<User>> {
        let local = match &*self.backend {
            Backend::Local(local) => local,
            Backend::Relay(_) => return Ok(None),
        };

        let admin_exists: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM user_groups ug \
             JOIN groups g ON ug.group_id = g.id \
             WHERE g.is_admin = 1 LIMIT 1",
        )
        .fetch_optional(&local.pool)
        .await?;
        if admin_exists.is_some() {
            return Ok(None);
        }

        let users = self.users();
        let user = match users.get_by_username(username, None).await? {
            Some(u) => u,
            None => users.create(username, password, display_name, None).await?,
        };
        users.set_admin(user.id, true, None).await?;
        Ok(Some(user))
    }
}

async fn run_migrations(pool: &SqlitePool, db_path: &Path) -> Result<()> {
    // 0005: users.id を INTEGER 連番から UUID (TEXT) へ移行する。0001 の
    // CREATE TABLE IF NOT EXISTS より先に判定しないと、旧スキーマが残ったまま
    // 素通りしてしまうため最初に実行する。
    migrate_users_to_uuid(pool, db_path).await?;

    // 0001_init creates tables (with `is_admin` column on `groups`) idempotently.
    // For databases predating `is_admin`, we ALTER TABLE if the column is missing.
    sqlx::query(include_str!("../migrations/0001_init.sql"))
        .execute(pool)
        .await?;

    let rows = sqlx::query("PRAGMA table_info(groups)")
        .fetch_all(pool)
        .await?;
    let has_is_admin = rows.iter().any(|r| {
        r.try_get::<String, _>("name")
            .map(|n| n == "is_admin")
            .unwrap_or(false)
    });
    if !has_is_admin {
        sqlx::query("ALTER TABLE groups ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await?;
    }

    // 0003 creates the service_clients table idempotently.
    sqlx::query(include_str!("../migrations/0003_service_clients.sql"))
        .execute(pool)
        .await?;

    // 0004: `users.token_version` for token revocation, ALTERed in for
    // databases predating the column (0001 includes it on fresh databases).
    let rows = sqlx::query("PRAGMA table_info(users)")
        .fetch_all(pool)
        .await?;
    let has_token_version = rows.iter().any(|r| {
        r.try_get::<String, _>("name")
            .map(|n| n == "token_version")
            .unwrap_or(false)
    });
    if !has_token_version {
        sqlx::query("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// `users.id` が旧スキーマ (INTEGER 連番) の場合、全ユーザーに UUID v7 を
/// 割り当ててテーブルを再構築し、`user_groups.user_id` の参照も引き継ぐ。
/// 実行前に DB ファイルを `<db>.pre-uuid.bak` へバックアップする。
async fn migrate_users_to_uuid(pool: &SqlitePool, db_path: &Path) -> Result<()> {
    let columns = sqlx::query("PRAGMA table_info(users)").fetch_all(pool).await?;
    if columns.is_empty() {
        // users テーブルがまだ無い(新規 DB)。0001 が TEXT id で作成する。
        return Ok(());
    }
    let id_is_integer = columns.iter().any(|r| {
        r.try_get::<String, _>("name").map(|n| n == "id").unwrap_or(false)
            && r.try_get::<String, _>("type")
                .map(|t| t.eq_ignore_ascii_case("INTEGER"))
                .unwrap_or(false)
    });
    if !id_is_integer {
        return Ok(());
    }
    let has_token_version = columns.iter().any(|r| {
        r.try_get::<String, _>("name")
            .map(|n| n == "token_version")
            .unwrap_or(false)
    });

    // 再構築前にファイルごとバックアップ(WAL の内容も含めるため VACUUM INTO)。
    let backup = db_path.with_extension("db.pre-uuid.bak");
    let _ = std::fs::remove_file(&backup);
    sqlx::query("VACUUM INTO ?")
        .bind(backup.to_string_lossy().to_string())
        .execute(pool)
        .await?;
    tracing_backup_note(&backup);

    // 外部キー制約の一時無効化はトランザクション外でのみ有効なため、
    // 単一コネクション上で OFF → 再構築 → ON の順に実行する。
    let mut conn = pool.acquire().await?;
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await?;

    let result: Result<()> = async {
        sqlx::query("BEGIN").execute(&mut *conn).await?;

        // 旧 id → 新 UUID の対応表。
        sqlx::query("CREATE TEMP TABLE id_map (old INTEGER PRIMARY KEY, new TEXT NOT NULL)")
            .execute(&mut *conn)
            .await?;
        let old_ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM users")
            .fetch_all(&mut *conn)
            .await?;
        for old in old_ids {
            sqlx::query("INSERT INTO id_map (old, new) VALUES (?, ?)")
                .bind(old)
                .bind(uuid::Uuid::now_v7().to_string())
                .execute(&mut *conn)
                .await?;
        }

        sqlx::query(
            "CREATE TABLE users_new (
                id TEXT PRIMARY KEY NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                is_active INTEGER NOT NULL DEFAULT 1,
                token_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&mut *conn)
        .await?;
        let token_version_expr = if has_token_version { "u.token_version" } else { "0" };
        sqlx::query(&format!(
            "INSERT INTO users_new \
             SELECT m.new, u.username, u.password_hash, u.display_name, u.is_active, \
                    {token_version_expr}, u.created_at, u.updated_at \
             FROM users u JOIN id_map m ON u.id = m.old",
        ))
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            "CREATE TABLE user_groups_new (
                user_id TEXT NOT NULL,
                group_id INTEGER NOT NULL,
                joined_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (user_id, group_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
            )",
        )
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "INSERT INTO user_groups_new \
             SELECT m.new, ug.group_id, ug.joined_at \
             FROM user_groups ug JOIN id_map m ON ug.user_id = m.old",
        )
        .execute(&mut *conn)
        .await?;

        sqlx::query("DROP TABLE user_groups").execute(&mut *conn).await?;
        sqlx::query("DROP TABLE users").execute(&mut *conn).await?;
        sqlx::query("ALTER TABLE users_new RENAME TO users")
            .execute(&mut *conn)
            .await?;
        sqlx::query("ALTER TABLE user_groups_new RENAME TO user_groups")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DROP TABLE id_map").execute(&mut *conn).await?;

        sqlx::query("COMMIT").execute(&mut *conn).await?;
        Ok(())
    }
    .await;

    if result.is_err() {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
    }

    let violations = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut *conn)
        .await?;
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *conn)
        .await?;
    result?;
    if !violations.is_empty() {
        return Err(Error::InvalidArgument(format!(
            "uuid migration left dangling foreign keys (backup kept at {})",
            backup.display()
        )));
    }
    Ok(())
}

fn tracing_backup_note(backup: &Path) {
    // tracing 依存を core に増やさず、標準エラーへ一度だけ知らせる。
    eprintln!(
        "user-permission: users.id を UUID へ移行します(バックアップ: {})",
        backup.display()
    );
}

/// `meta` テーブルから server_id を読み出し、無ければ UUID v7 を生成して永続化する。
async fn load_or_create_server_id(pool: &SqlitePool) -> Result<String> {
    if let Some(id) =
        sqlx::query_scalar::<_, String>("SELECT value FROM meta WHERE key = 'server_id'")
            .fetch_optional(pool)
            .await?
    {
        return Ok(id);
    }
    let id = uuid::Uuid::now_v7().to_string();
    // 競合時 (別コネクションが先に生成) は既存値を採用する。
    sqlx::query("INSERT OR IGNORE INTO meta (key, value) VALUES ('server_id', ?)")
        .bind(&id)
        .execute(pool)
        .await?;
    sqlx::query_scalar::<_, String>("SELECT value FROM meta WHERE key = 'server_id'")
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

impl Backend {
    pub(crate) fn as_local(&self) -> Result<&LocalBackend> {
        match self {
            Backend::Local(local) => Ok(local),
            Backend::Relay(_) => Err(Error::InvalidArgument(
                "operation requires a local backend".into(),
            )),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn as_relay(&self) -> Result<&RelayBackend> {
        match self {
            Backend::Relay(relay) => Ok(relay),
            Backend::Local(_) => Err(Error::InvalidArgument(
                "operation requires a relay backend".into(),
            )),
        }
    }
}

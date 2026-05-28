use std::path::Path;
use std::sync::Arc;

use jsonwebtoken::Algorithm;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::error::{Error, Result};
use crate::group::GroupManager;
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
    pub async fn open_local(
        db_path: impl AsRef<Path>,
        secret_path: Option<impl AsRef<Path>>,
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

        run_migrations(&pool).await?;

        let token_manager = match secret_path {
            Some(p) => Some(TokenManager::from_file(p, Algorithm::HS256)?),
            None => None,
        };

        Ok(Self {
            backend: Arc::new(Backend::Local(LocalBackend {
                pool,
                token_manager,
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

    /// For relay backends, log in and store the access token internally.
    pub async fn login(&self, username: &str, password: &str) -> Result<String> {
        match &*self.backend {
            Backend::Relay(relay) => relay.login(username, password).await,
            Backend::Local(_) => Err(Error::InvalidArgument(
                "login() is only valid for relay backends".into(),
            )),
        }
    }

    /// For relay backends, authenticate as a service via the client-credentials
    /// grant and store the issued access token internally. The credentials are
    /// also retained so the token can be transparently refreshed on a 401.
    pub async fn login_client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<String> {
        match &*self.backend {
            Backend::Relay(relay) => {
                relay
                    .login_client_credentials(client_id, client_secret)
                    .await
            }
            Backend::Local(_) => Err(Error::InvalidArgument(
                "login_client_credentials() is only valid for relay backends".into(),
            )),
        }
    }

    /// Resolve a bearer token to its owning [`User`], backend-agnostically.
    ///
    /// - local: verifies the JWT signature and expiry with the configured
    ///   [`TokenManager`], then loads the user named by the `sub` claim.
    /// - relay: delegates to the server via `GET /me`, which performs the same
    ///   validation server-side.
    ///
    /// Returns `Ok(None)` for an invalid, expired, or non-user (service) token
    /// in both cases. Local without a token manager yields
    /// [`Error::MissingTokenManager`].
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
                    .and_then(|s| s.parse::<i64>().ok());
                let Some(id) = user_id else {
                    return Ok(None);
                };
                match self.users().get_by_id(id, None).await? {
                    Some(user) if user.is_active => Ok(Some(Principal::User(user))),
                    _ => Ok(None),
                }
            }
            Backend::Relay(relay) => relay.introspect(token).await,
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
            "SELECT ug.user_id FROM user_groups ug \
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

async fn run_migrations(pool: &SqlitePool) -> Result<()> {
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

    Ok(())
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

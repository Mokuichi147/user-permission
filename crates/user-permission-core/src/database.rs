use std::path::Path;
use std::sync::Arc;

use jsonwebtoken::Algorithm;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::error::{Error, Result};
use crate::group::GroupManager;
use crate::relay::RelayBackend;
use crate::token::TokenManager;
use crate::user::UserManager;

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

impl Database {
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

    pub fn token_manager(&self) -> Result<&TokenManager> {
        match &*self.backend {
            Backend::Local(local) => local
                .token_manager
                .as_ref()
                .ok_or(Error::MissingTokenManager),
            Backend::Relay(_) => Err(Error::MissingTokenManager),
        }
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

    pub fn is_local(&self) -> bool {
        matches!(&*self.backend, Backend::Local(_))
    }

    pub fn is_relay(&self) -> bool {
        matches!(&*self.backend, Backend::Relay(_))
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

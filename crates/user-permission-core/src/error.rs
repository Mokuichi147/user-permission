use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("token manager not configured (Database::open_local requires a secret)")]
    MissingTokenManager,

    #[error("database not connected")]
    NotConnected,

    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("password hash error: {0}")]
    Password(String),

    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("relay returned status {status}: {body}")]
    Relay { status: u16, body: String },

    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl Error {
    pub fn is_unique_violation(&self) -> bool {
        match self {
            Error::Conflict(_) => true,
            Error::Db(sqlx::Error::Database(e)) => e
                .code()
                .map(|c| c == "2067" || c == "1555") // SQLITE_CONSTRAINT_UNIQUE / PRIMARYKEY
                .unwrap_or(false),
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

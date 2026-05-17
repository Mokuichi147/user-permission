//! `user-permission-core` – async user / group management with SQLite or
//! HTTP relay backend. axum-based HTTP server and CLI live in the
//! companion [`user_permission`](https://docs.rs/user-permission) crate.
//!
//! ```no_run
//! use std::time::Duration;
//! use user_permission_core::Database;
//!
//! # async fn run() -> user_permission_core::Result<()> {
//! let db = Database::open_local("app.db", Some("secret.key")).await?;
//! let user = db.users().create("alice", "password123", "Alice").await?;
//! let token = db
//!     .users()
//!     .authenticate("alice", "password123", Duration::from_secs(3600))
//!     .await?;
//! assert!(token.is_some());
//! # let _ = user;
//! # Ok(())
//! # }
//! ```

mod database;
mod error;
mod group;
pub mod password;
mod relay;
mod user;
pub mod token;

pub use database::Database;
pub use error::{Error, Result};
pub use group::{Group, GroupManager, GroupUpdate};
pub use token::{load_or_create_secret, BaseClaims, TokenManager};
pub use user::{User, UserManager, UserUpdate};

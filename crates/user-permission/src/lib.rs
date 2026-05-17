//! `user-permission` — axum REST API + WebUI library plus a ready-to-run
//! server binary (`cargo install user-permission`).
//!
//! Core data types (`Database`, `User`, `Group`, etc.) live in the sibling
//! [`user_permission_core`] crate; this crate adds the HTTP layer.
//!
//! ```ignore
//! use user_permission_core::Database;
//! use user_permission::{build_app, WebConfig};
//!
//! let db = Database::open_local("app.db", Some("secret.key")).await?;
//! let app = build_app(db, WebConfig::default());
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:8000").await?;
//! axum::serve(listener, app).await?;
//! ```

pub mod api;
pub mod auth;
pub mod error;
pub mod state;
pub mod webui;

use std::sync::Arc;

use axum::Router;
use user_permission_core::Database;

pub use error::ApiError;
pub use state::{AppState, WebConfig};

/// Build the full axum router: REST API mounted at `config.api_prefix`,
/// optional HTMX WebUI mounted at `config.webui_prefix`, and a `/` →
/// `webui_prefix` redirect when both prefixes are non-empty.
pub fn build_app(db: Database, config: WebConfig) -> Router {
    let webui_enabled = config.webui_enabled;
    let api_prefix = config.api_prefix.clone();
    let webui_prefix = config.webui_prefix.clone();
    let state = Arc::new(AppState { db, config });

    let mut app = Router::new();

    let api_router: Router<Arc<AppState>> = api::router();
    if api_prefix.is_empty() {
        app = app.merge(api_router.clone().with_state(state.clone()));
    } else {
        app = app.nest(&api_prefix, api_router.with_state(state.clone()));
    }

    if webui_enabled {
        let webui_router: Router<Arc<AppState>> = webui::router(&webui_prefix);
        app = app.merge(webui_router.with_state(state.clone()));
        if !api_prefix.is_empty() || !webui_prefix.is_empty() {
            let target = if webui_prefix.is_empty() {
                "/".to_string()
            } else {
                format!("{}/", webui_prefix.trim_end_matches('/'))
            };
            app = app.route(
                "/",
                axum::routing::get(move || {
                    let target = target.clone();
                    async move { axum::response::Redirect::to(&target) }
                }),
            );
        }
    }

    app
}

/// Convenience constructor for an API-only router with no nesting.
pub fn api_router(db: Database, config: WebConfig) -> Router {
    let state = Arc::new(AppState { db, config });
    api::router().with_state(state)
}

use std::time::Duration;

use user_permission_core::Database;

#[derive(Clone)]
pub struct WebConfig {
    pub api_prefix: String,
    pub webui_prefix: String,
    pub webui_enabled: bool,
    pub token_expires: Duration,
    pub webui_token_expires: Duration,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            api_prefix: String::new(),
            webui_prefix: "/ui".to_string(),
            webui_enabled: false,
            token_expires: Duration::from_secs(3600),
            webui_token_expires: Duration::from_secs(86_400),
        }
    }
}

pub struct AppState {
    pub db: Database,
    pub config: WebConfig,
}

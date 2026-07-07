use std::time::Duration;

use user_permission_core::Database;

#[derive(Clone)]
pub struct WebConfig {
    pub api_prefix: String,
    pub webui_prefix: String,
    pub webui_enabled: bool,
    pub token_expires: Duration,
    pub webui_token_expires: Duration,
    /// WebUI のセッション Cookie に `Secure` 属性を付ける。HTTPS で運用する
    /// 場合は必ず有効にすること。`http://localhost` などの開発環境では
    /// Cookie が送信されなくなるため既定は無効。
    pub cookie_secure: bool,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            api_prefix: String::new(),
            webui_prefix: "/ui".to_string(),
            webui_enabled: false,
            token_expires: Duration::from_secs(3600),
            webui_token_expires: Duration::from_secs(86_400),
            cookie_secure: false,
        }
    }
}

pub struct AppState {
    pub db: Database,
    pub config: WebConfig,
}

use std::time::Duration;

use user_permission_core::Database;

use crate::login_guard::LoginGuard;

#[derive(Clone)]
pub struct WebConfig {
    pub api_prefix: String,
    pub webui_prefix: String,
    pub webui_enabled: bool,
    pub token_expires: Duration,
    pub webui_token_expires: Duration,
    /// 同一ユーザー名（またはサービスの client_id）で連続してログインに
    /// 失敗できる回数。超えると `login_lockout` の間ロックされる。
    /// 0 でレート制限を無効化。
    pub login_max_failures: u32,
    /// ロックアウトの継続時間。
    pub login_lockout: Duration,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            api_prefix: String::new(),
            webui_prefix: "/ui".to_string(),
            webui_enabled: false,
            token_expires: Duration::from_secs(3600),
            webui_token_expires: Duration::from_secs(86_400),
            login_max_failures: 5,
            login_lockout: Duration::from_secs(300),
        }
    }
}

pub struct AppState {
    pub db: Database,
    pub config: WebConfig,
    pub login_guard: LoginGuard,
}

impl AppState {
    pub fn new(db: Database, config: WebConfig) -> Self {
        let login_guard = LoginGuard::new(config.login_max_failures, config.login_lockout);
        Self {
            db,
            config,
            login_guard,
        }
    }
}

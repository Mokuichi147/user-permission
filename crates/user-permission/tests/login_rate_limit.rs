use std::time::Duration;

use user_permission::{build_app, WebConfig};
use user_permission_core::Database;

/// ロックアウト閾値 3 回・ロック 60 秒でサーバーを起動する。
async fn spawn_server() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open_local(dir.path().join("test.db"), Some(dir.path().join("secret.key")))
        .await
        .expect("open db");
    db.users()
        .create("admin", "pw", "Admin", None)
        .await
        .unwrap();
    db.users().create("bob", "pw", "Bob", None).await.unwrap();

    let config = WebConfig {
        webui_enabled: true,
        login_max_failures: 3,
        login_lockout: Duration::from_secs(60),
        ..Default::default()
    };
    let app = build_app(db, config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), dir)
}

async fn try_login(client: &reqwest::Client, base: &str, user: &str, pw: &str) -> u16 {
    client
        .post(format!("{base}/token"))
        .form(&[("username", user), ("password", pw)])
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn locks_out_after_consecutive_failures() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    for _ in 0..3 {
        assert_eq!(try_login(&client, &base, "bob", "wrong").await, 401);
    }
    // ロック中は正しいパスワードでも 429
    assert_eq!(try_login(&client, &base, "bob", "pw").await, 429);
    // 他ユーザーには影響しない
    assert_eq!(try_login(&client, &base, "admin", "pw").await, 200);
}

#[tokio::test]
async fn success_resets_failure_count() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    assert_eq!(try_login(&client, &base, "bob", "wrong").await, 401);
    assert_eq!(try_login(&client, &base, "bob", "wrong").await, 401);
    assert_eq!(try_login(&client, &base, "bob", "pw").await, 200);
    // 成功でリセットされるので、再び閾値まで失敗できる
    assert_eq!(try_login(&client, &base, "bob", "wrong").await, 401);
    assert_eq!(try_login(&client, &base, "bob", "pw").await, 200);
}

#[tokio::test]
async fn webui_login_shares_the_same_guard() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // API 側で 3 回失敗させると WebUI 側もロックされる
    for _ in 0..3 {
        assert_eq!(try_login(&client, &base, "bob", "wrong").await, 401);
    }
    let resp = client
        .post(format!("{base}/ui/login"))
        .form(&[("username", "bob"), ("password", "pw")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 429);
}

#[tokio::test]
async fn client_credentials_grant_is_also_limited() {
    let (base, _dir) = spawn_server().await;
    let client = reqwest::Client::new();

    let attempt = |id: &'static str| {
        let client = client.clone();
        let base = base.clone();
        async move {
            client
                .post(format!("{base}/token"))
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", id),
                    ("client_secret", "wrong"),
                ])
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    for _ in 0..3 {
        assert_eq!(attempt("svc_unknown").await, 401);
    }
    assert_eq!(attempt("svc_unknown").await, 429);
}

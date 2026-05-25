use serde_json::json;
use user_permission::{build_app, WebConfig};
use user_permission_core::Database;

/// Boot a server with a local backend on an ephemeral port. Creates an admin
/// user `admin/pw` (first user is auto-admin) plus a second user `bob`.
async fn spawn_server() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open_local(dir.path().join("test.db"), Some(dir.path().join("secret.key")))
        .await
        .expect("open db");
    db.users().create("admin", "pw", "Admin", None).await.unwrap();
    db.users().create("bob", "pw", "Bob", None).await.unwrap();

    let app = build_app(db, WebConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), dir)
}

async fn admin_token(client: &reqwest::Client, base: &str) -> String {
    let resp = client
        .post(format!("{base}/token"))
        .form(&[("username", "admin"), ("password", "pw")])
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    resp.json::<serde_json::Value>()
        .await
        .unwrap()
        .get("access_token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

/// Create a service client (admin-only) and return (client_id, client_secret).
async fn create_client(
    client: &reqwest::Client,
    base: &str,
    admin: &str,
    scopes: &[&str],
) -> (String, String) {
    let resp = client
        .post(format!("{base}/service-clients"))
        .bearer_auth(admin)
        .json(&json!({ "name": "svc", "scopes": scopes }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    (
        body["client_id"].as_str().unwrap().to_string(),
        body["client_secret"].as_str().unwrap().to_string(),
    )
}

async fn client_credentials_token(
    client: &reqwest::Client,
    base: &str,
    client_id: &str,
    secret: &str,
) -> String {
    let resp = client
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", secret),
        ])
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "client_credentials grant failed");
    resp.json::<serde_json::Value>()
        .await
        .unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn service_token_scope_enforced() {
    let (base, _dir) = spawn_server().await;
    let http = reqwest::Client::new();
    let admin = admin_token(&http, &base).await;

    // users:read only.
    let (cid, secret) = create_client(&http, &base, &admin, &["users:read"]).await;
    let token = client_credentials_token(&http, &base, &cid, &secret).await;

    // Granted scope: GET /users works.
    let resp = http
        .get(format!("{base}/users"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "users:read should allow GET /users");

    // Missing scope: GET /groups is forbidden.
    let resp = http
        .get(format!("{base}/groups"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);

    // Admin endpoints reject service tokens regardless of scope.
    let resp = http
        .post(format!("{base}/groups"))
        .bearer_auth(&token)
        .json(&json!({"name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);

    // /me has no backing user for a service token.
    let resp = http
        .get(format!("{base}/me"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unknown_scope_rejected_at_creation() {
    let (base, _dir) = spawn_server().await;
    let http = reqwest::Client::new();
    let admin = admin_token(&http, &base).await;

    let resp = http
        .post(format!("{base}/service-clients"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "bad", "scopes": ["users:write"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revoked_client_cannot_obtain_token() {
    let (base, _dir) = spawn_server().await;
    let http = reqwest::Client::new();
    let admin = admin_token(&http, &base).await;

    let resp = http
        .post(format!("{base}/service-clients"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "svc", "scopes": ["users:read"] }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_i64().unwrap();
    let cid = body["client_id"].as_str().unwrap().to_string();
    let secret = body["client_secret"].as_str().unwrap().to_string();

    // Revoke.
    let resp = http
        .delete(format!("{base}/service-clients/{id}"))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    // No new token can be issued.
    let resp = http
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &cid),
            ("client_secret", &secret),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn relay_uses_client_credentials() {
    let (base, _dir) = spawn_server().await;
    let http = reqwest::Client::new();
    let admin = admin_token(&http, &base).await;
    let (cid, secret) = create_client(&http, &base, &admin, &["users:read"]).await;

    // A downstream service authenticates with client credentials and reads the
    // user directory through the relay backend.
    let relay = Database::open_relay(&base).unwrap();
    relay.login_client_credentials(&cid, &secret).await.unwrap();

    let bob = relay
        .users()
        .get_by_username("bob", None)
        .await
        .unwrap()
        .expect("bob should be found");
    assert_eq!(bob.username, "bob");
}

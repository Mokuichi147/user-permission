use serde_json::{json, Value};
use user_permission::{build_app, WebConfig};
use user_permission_core::Database;

/// admin（管理者）/ bob・carol（一般）と、bob だけが所属する editors
/// グループを持つサーバーを起動する。
async fn spawn_server() -> (String, uuid::Uuid, uuid::Uuid, i64, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open_local(dir.path().join("test.db"), Some(dir.path().join("secret.key")))
        .await
        .expect("open db");
    let admin = db
        .users()
        .create("admin", "pw-123456", "Admin", None)
        .await
        .unwrap();
    let bob = db.users().create("bob", "pw-123456", "Bob", None).await.unwrap();
    db.users().create("carol", "pw-123456", "Carol", None).await.unwrap();
    let editors = db
        .groups()
        .create("editors", "Editors", false, None)
        .await
        .unwrap();
    db.groups().add_user(editors.id, bob.id, None).await.unwrap();

    let app = build_app(db, WebConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), admin.id, bob.id, editors.id, dir)
}

async fn token_for(client: &reqwest::Client, base: &str, user: &str) -> String {
    let resp = client
        .post(format!("{base}/token"))
        .form(&[("username", user), ("password", "pw-123456")])
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    resp.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn get_json(client: &reqwest::Client, url: &str, token: &str) -> (u16, Value) {
    let resp = client.get(url).bearer_auth(token).send().await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn non_admin_sees_only_self_in_user_list() {
    let (base, _admin_id, bob_id, _gid, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let bob = token_for(&client, &base, "bob").await;

    let (status, body) = get_json(&client, &format!("{base}/users"), &bob).await;
    assert_eq!(status, 200);
    let users = body.as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["id"].as_str(), Some(bob_id.to_string().as_str()));

    // ユーザー名検索でも他人は見えない
    let (status, body) = get_json(&client, &format!("{base}/users?username=admin"), &bob).await;
    assert_eq!(status, 200);
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn non_admin_cannot_fetch_other_users() {
    let (base, admin_id, bob_id, _gid, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let bob = token_for(&client, &base, "bob").await;

    let (status, _) = get_json(&client, &format!("{base}/users/{admin_id}"), &bob).await;
    assert_eq!(status, 403);
    let (status, _) = get_json(&client, &format!("{base}/users/{bob_id}"), &bob).await;
    assert_eq!(status, 200);

    let (status, _) = get_json(&client, &format!("{base}/users/{admin_id}/groups"), &bob).await;
    assert_eq!(status, 403);
    let (status, _) = get_json(&client, &format!("{base}/users/{bob_id}/groups"), &bob).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn non_admin_sees_only_own_groups() {
    let (base, _admin_id, _bob_id, editors_id, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let bob = token_for(&client, &base, "bob").await;
    let carol = token_for(&client, &base, "carol").await;

    // bob は editors のみ見える
    let (status, body) = get_json(&client, &format!("{base}/groups"), &bob).await;
    assert_eq!(status, 200);
    let groups = body.as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["id"].as_i64(), Some(editors_id));

    // メンバーの bob は閲覧可、非メンバーの carol は 403
    let (status, _) =
        get_json(&client, &format!("{base}/groups/{editors_id}/members"), &bob).await;
    assert_eq!(status, 200);
    let (status, _) =
        get_json(&client, &format!("{base}/groups/{editors_id}/members"), &carol).await;
    assert_eq!(status, 403);
    let (status, _) = get_json(&client, &format!("{base}/groups/{editors_id}"), &carol).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn admin_and_service_scope_see_everything() {
    let (base, _admin_id, _bob_id, editors_id, _dir) = spawn_server().await;
    let client = reqwest::Client::new();
    let admin = token_for(&client, &base, "admin").await;

    let (status, body) = get_json(&client, &format!("{base}/users"), &admin).await;
    assert_eq!(status, 200);
    assert_eq!(body.as_array().unwrap().len(), 3);
    let (status, body) = get_json(&client, &format!("{base}/groups"), &admin).await;
    assert_eq!(status, 200);
    assert_eq!(body.as_array().unwrap().len(), 2); // admin + editors

    // users:read / groups:read を持つサービストークンも全体を見られる
    let resp = client
        .post(format!("{base}/service-clients"))
        .bearer_auth(&admin)
        .json(&json!({ "name": "svc", "scopes": ["users:read", "groups:read"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);
    let created: Value = resp.json().await.unwrap();
    let resp = client
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", created["client_id"].as_str().unwrap()),
            ("client_secret", created["client_secret"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap();
    let svc = resp.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = get_json(&client, &format!("{base}/users"), &svc).await;
    assert_eq!(status, 200);
    assert_eq!(body.as_array().unwrap().len(), 3);
    let (status, _) =
        get_json(&client, &format!("{base}/groups/{editors_id}/members"), &svc).await;
    assert_eq!(status, 200);
}

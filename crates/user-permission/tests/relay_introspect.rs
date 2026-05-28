use user_permission::{build_app, WebConfig};
use user_permission_core::{Database, Principal, SCOPE_USERS_READ};

/// Boot a real server (local backend) on an ephemeral port and return its base
/// URL, the issued service-client credentials, and the temp dir (kept alive).
async fn spawn_server() -> (String, (String, String), tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open_local(dir.path().join("test.db"), Some(dir.path().join("secret.key")))
        .await
        .expect("open db");

    // First user becomes admin.
    db.users().create("alice", "pw", "Alice", None).await.unwrap();
    let (client, secret) = db
        .service_clients()
        .create("svc", &[SCOPE_USERS_READ.to_string()], None)
        .await
        .unwrap();

    let app = build_app(db, WebConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}"), (client.client_id, secret), dir)
}

#[tokio::test]
async fn relay_introspect_classifies_principals() {
    let (base_url, (client_id, client_secret), _dir) = spawn_server().await;
    let relay = Database::open_relay(&base_url).unwrap();

    // A user token resolves to Principal::User over the relay.
    let user_token = relay.login("alice", "pw").await.unwrap();
    match relay.resolve_principal(&user_token).await.unwrap() {
        Some(Principal::User(user)) => assert_eq!(user.username, "alice"),
        other => panic!("expected a user principal, got {other:?}"),
    }

    // A service token resolves to Principal::Service with its granted scopes.
    let svc_token = relay
        .login_client_credentials(&client_id, &client_secret)
        .await
        .unwrap();
    match relay.resolve_principal(&svc_token).await.unwrap() {
        Some(Principal::Service { client_id: cid, scopes }) => {
            assert_eq!(cid, client_id);
            assert_eq!(scopes, vec![SCOPE_USERS_READ.to_string()]);
        }
        other => panic!("expected a service principal, got {other:?}"),
    }

    // An invalid token resolves to None (mirrors the local backend).
    assert!(relay
        .resolve_principal("not-a-token")
        .await
        .unwrap()
        .is_none());
}

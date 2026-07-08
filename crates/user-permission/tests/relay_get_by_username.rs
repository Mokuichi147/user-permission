use user_permission::{build_app, WebConfig};
use user_permission_core::Database;

/// Boot the server with a local backend on an ephemeral port and return its
/// base URL plus the temp dir (kept alive for the duration of the test).
async fn spawn_server() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open_local(dir.path().join("test.db"), Some(dir.path().join("secret.key")))
        .await
        .expect("open db");

    // First user becomes admin; create a couple of users to search for.
    db.users().create("alice", "pw-123456", "Alice", None).await.unwrap();
    db.users().create("bob", "pw-123456", "Bob", None).await.unwrap();

    let app = build_app(db, WebConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}"), dir)
}

#[tokio::test]
async fn relay_get_by_username_resolves_user() {
    let (base_url, _dir) = spawn_server().await;

    let relay = Database::open_relay(&base_url).unwrap();
    relay
        .login("alice", "pw-123456", std::time::Duration::from_secs(3600))
        .await
        .unwrap()
        .expect("login should succeed");

    let found = relay
        .users()
        .get_by_username("bob", None)
        .await
        .expect("relay get_by_username should succeed")
        .expect("bob should exist");
    assert_eq!(found.username, "bob");
    assert_eq!(found.display_name, "Bob");

    let missing = relay
        .users()
        .get_by_username("nobody", None)
        .await
        .expect("relay get_by_username should succeed");
    assert!(missing.is_none(), "unknown username should resolve to None");
}

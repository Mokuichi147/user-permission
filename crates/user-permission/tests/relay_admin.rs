use std::time::Duration;

use user_permission::{build_app, WebConfig};
use user_permission_core::Database;

/// Boot a real server (local backend) on an ephemeral port. The first user
/// becomes admin. Returns the base URL, bob's id, and the temp dir.
async fn spawn_server() -> (String, i64, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open_local(dir.path().join("test.db"), Some(dir.path().join("secret.key")))
        .await
        .expect("open db");

    db.users().create("alice", "pw", "Alice", None).await.unwrap();
    db.users().set_admin(1, true, None).await.unwrap();
    let bob = db.users().create("bob", "pw", "Bob", None).await.unwrap();

    let app = build_app(db, WebConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}"), bob.id, dir)
}

#[tokio::test]
async fn relay_admin_operations_round_trip() {
    let (base_url, bob_id, _dir) = spawn_server().await;
    let relay = Database::open_relay(&base_url).unwrap();
    let token = relay
        .login("alice", "pw", Duration::from_secs(3600))
        .await
        .unwrap()
        .expect("admin login");
    let tok = Some(token.as_str());

    // get_by_name and list_admin_groups work over the relay.
    let admin_group = relay
        .groups()
        .get_by_name("admin", tok)
        .await
        .unwrap()
        .expect("admin group should exist");
    assert!(admin_group.is_admin);
    let admin_groups = relay.groups().list_admin_groups(tok).await.unwrap();
    assert!(admin_groups.iter().any(|g| g.id == admin_group.id));

    // set_admin promotes bob through the relay, observable via is_admin.
    assert!(!relay.users().is_admin(bob_id, tok).await.unwrap());
    relay.users().set_admin(bob_id, true, tok).await.unwrap();
    assert!(relay.users().is_admin(bob_id, tok).await.unwrap());

    // ...and demotes him again.
    relay.users().set_admin(bob_id, false, tok).await.unwrap();
    assert!(!relay.users().is_admin(bob_id, tok).await.unwrap());
}

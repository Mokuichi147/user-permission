use std::time::Duration;

use user_permission_core::{Database, GroupUpdate, UserUpdate};

async fn open_test_db() -> (Database, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let secret_path = dir.path().join("secret.key");
    let db = Database::open_local(&db_path, Some(&secret_path))
        .await
        .expect("open db");
    (db, dir)
}

#[tokio::test]
async fn first_user_auto_admin() {
    let (db, _dir) = open_test_db().await;
    let alice = db.users().create("alice", "pw", "Alice").await.unwrap();
    assert!(db.users().is_admin(alice.id).await.unwrap());

    let bob = db.users().create("bob", "pw", "Bob").await.unwrap();
    assert!(!db.users().is_admin(bob.id).await.unwrap());
}

#[tokio::test]
async fn user_crud() {
    let (db, _dir) = open_test_db().await;
    let alice = db.users().create("alice", "pw", "Alice").await.unwrap();
    assert_eq!(alice.username, "alice");
    assert_eq!(alice.display_name, "Alice");
    assert!(alice.is_active);

    let fetched = db.users().get_by_id(alice.id).await.unwrap().unwrap();
    assert_eq!(fetched.username, "alice");

    let by_name = db.users().get_by_username("alice").await.unwrap().unwrap();
    assert_eq!(by_name.id, alice.id);

    let updated = db
        .users()
        .update(
            alice.id,
            UserUpdate {
                display_name: Some("Alice Smith".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.display_name, "Alice Smith");

    let users = db.users().list_all().await.unwrap();
    assert_eq!(users.len(), 1);

    let deleted = db.users().delete(alice.id).await.unwrap();
    assert!(deleted);
    assert!(db.users().get_by_id(alice.id).await.unwrap().is_none());
}

#[tokio::test]
async fn duplicate_username_conflict() {
    let (db, _dir) = open_test_db().await;
    db.users().create("alice", "pw", "").await.unwrap();
    let err = db.users().create("alice", "pw2", "").await.unwrap_err();
    assert!(err.is_unique_violation(), "expected unique violation, got {err}");
}

#[tokio::test]
async fn authenticate_and_verify() {
    let (db, _dir) = open_test_db().await;
    db.users().create("alice", "pw", "").await.unwrap();
    let token = db
        .users()
        .authenticate("alice", "pw", Duration::from_secs(60))
        .await
        .unwrap()
        .expect("token");
    let claims = db.token_manager().unwrap().verify_token(&token).unwrap();
    assert_eq!(claims["username"], serde_json::Value::String("alice".into()));
    assert_eq!(claims["is_admin"], serde_json::Value::Bool(true)); // first user is admin

    assert!(db
        .users()
        .authenticate("alice", "wrong", Duration::from_secs(60))
        .await
        .unwrap()
        .is_none());
    assert!(db
        .users()
        .authenticate("nobody", "pw", Duration::from_secs(60))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn group_crud_and_membership() {
    let (db, _dir) = open_test_db().await;
    let alice = db.users().create("alice", "pw", "").await.unwrap(); // admin
    let bob = db.users().create("bob", "pw", "").await.unwrap();

    let editors = db
        .groups()
        .create("editors", "Editors", false)
        .await
        .unwrap();
    assert!(!editors.is_admin);

    assert!(db.groups().add_user(editors.id, bob.id).await.unwrap());
    let members = db.groups().get_members(editors.id).await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].username, "bob");

    let bobs_groups = db.groups().get_user_groups(bob.id).await.unwrap();
    assert_eq!(bobs_groups.len(), 1);
    assert_eq!(bobs_groups[0].name, "editors");

    // alice (first user) is in the auto-created admin group.
    let alice_groups = db.groups().get_user_groups(alice.id).await.unwrap();
    assert_eq!(alice_groups.len(), 1);
    assert!(alice_groups[0].is_admin);

    assert!(db.groups().remove_user(editors.id, bob.id).await.unwrap());
    assert!(db.groups().get_members(editors.id).await.unwrap().is_empty());

    let updated = db
        .groups()
        .update(
            editors.id,
            GroupUpdate {
                description: Some("New desc".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.description, "New desc");

    assert!(db.groups().delete(editors.id).await.unwrap());
}

#[tokio::test]
async fn promote_and_demote_admin() {
    let (db, _dir) = open_test_db().await;
    let _alice = db.users().create("alice", "pw", "").await.unwrap(); // admin
    let bob = db.users().create("bob", "pw", "").await.unwrap();

    assert!(!db.users().is_admin(bob.id).await.unwrap());

    db.users().set_admin(bob.id, true).await.unwrap();
    assert!(db.users().is_admin(bob.id).await.unwrap());

    db.users().set_admin(bob.id, false).await.unwrap();
    assert!(!db.users().is_admin(bob.id).await.unwrap());
}

#[tokio::test]
async fn legacy_db_missing_is_admin_column() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("legacy.db");

    // Simulate a pre-v0.2 database without the is_admin column.
    let conn = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rwc", db_path.display()))
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE users (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            username TEXT NOT NULL UNIQUE,\
            password_hash TEXT NOT NULL,\
            display_name TEXT NOT NULL DEFAULT '',\
            is_active INTEGER NOT NULL DEFAULT 1,\
            created_at TEXT NOT NULL DEFAULT (datetime('now')),\
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))\
        )",
    )
    .execute(&conn)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE groups (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            name TEXT NOT NULL UNIQUE,\
            description TEXT NOT NULL DEFAULT '',\
            created_at TEXT NOT NULL DEFAULT (datetime('now')),\
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))\
        )",
    )
    .execute(&conn)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE user_groups (\
            user_id INTEGER NOT NULL,\
            group_id INTEGER NOT NULL,\
            joined_at TEXT NOT NULL DEFAULT (datetime('now')),\
            PRIMARY KEY (user_id, group_id)\
        )",
    )
    .execute(&conn)
    .await
    .unwrap();
    conn.close().await;

    // Now open with the new version: the ALTER should add is_admin.
    let secret = dir.path().join("secret.key");
    let db = Database::open_local(&db_path, Some(&secret)).await.unwrap();
    let alice = db.users().create("alice", "pw", "").await.unwrap();
    // alice is the first user → automatically admin
    assert!(db.users().is_admin(alice.id).await.unwrap());
}

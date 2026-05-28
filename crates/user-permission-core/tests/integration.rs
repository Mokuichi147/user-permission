use std::time::Duration;

use user_permission_core::{Database, GroupUpdate, Principal, UserUpdate, SCOPE_USERS_READ};

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
    let alice = db
        .users()
        .create("alice", "pw", "Alice", None)
        .await
        .unwrap();
    assert!(db.users().is_admin(alice.id, None).await.unwrap());

    let bob = db.users().create("bob", "pw", "Bob", None).await.unwrap();
    assert!(!db.users().is_admin(bob.id, None).await.unwrap());
}

#[tokio::test]
async fn user_crud() {
    let (db, _dir) = open_test_db().await;
    let alice = db
        .users()
        .create("alice", "pw", "Alice", None)
        .await
        .unwrap();
    assert_eq!(alice.username, "alice");
    assert_eq!(alice.display_name, "Alice");
    assert!(alice.is_active);

    let fetched = db.users().get_by_id(alice.id, None).await.unwrap().unwrap();
    assert_eq!(fetched.username, "alice");

    let by_name = db
        .users()
        .get_by_username("alice", None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_name.id, alice.id);

    let updated = db
        .users()
        .update(
            alice.id,
            UserUpdate {
                display_name: Some("Alice Smith".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.display_name, "Alice Smith");

    let users = db.users().list_all(None).await.unwrap();
    assert_eq!(users.len(), 1);

    let deleted = db.users().delete(alice.id, None).await.unwrap();
    assert!(deleted);
    assert!(db
        .users()
        .get_by_id(alice.id, None)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn duplicate_username_conflict() {
    let (db, _dir) = open_test_db().await;
    db.users().create("alice", "pw", "", None).await.unwrap();
    let err = db
        .users()
        .create("alice", "pw2", "", None)
        .await
        .unwrap_err();
    assert!(
        err.is_unique_violation(),
        "expected unique violation, got {err}"
    );
}

#[tokio::test]
async fn authenticate_and_verify() {
    let (db, _dir) = open_test_db().await;
    db.users().create("alice", "pw", "", None).await.unwrap();
    let token = db
        .login("alice", "pw", Duration::from_secs(60))
        .await
        .unwrap()
        .expect("token");
    let principal = db.resolve_principal(&token).await.unwrap().expect("principal");
    let user_permission_core::Principal::User(user) = principal else {
        panic!("expected a user principal");
    };
    assert_eq!(user.username, "alice");
    assert!(
        db.users().is_admin(user.id, None).await.unwrap(),
        "first user is admin"
    );

    assert!(db
        .login("alice", "wrong", Duration::from_secs(60))
        .await
        .unwrap()
        .is_none());
    assert!(db
        .login("nobody", "pw", Duration::from_secs(60))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn group_crud_and_membership() {
    let (db, _dir) = open_test_db().await;
    let alice = db.users().create("alice", "pw", "", None).await.unwrap(); // admin
    let bob = db.users().create("bob", "pw", "", None).await.unwrap();

    let editors = db
        .groups()
        .create("editors", "Editors", false, None)
        .await
        .unwrap();
    assert!(!editors.is_admin);

    assert!(db
        .groups()
        .add_user(editors.id, bob.id, None)
        .await
        .unwrap());
    let members = db.groups().get_members(editors.id, None).await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].username, "bob");

    let bobs_groups = db.groups().get_user_groups(bob.id, None).await.unwrap();
    assert_eq!(bobs_groups.len(), 1);
    assert_eq!(bobs_groups[0].name, "editors");

    // alice (first user) is in the auto-created admin group.
    let alice_groups = db.groups().get_user_groups(alice.id, None).await.unwrap();
    assert_eq!(alice_groups.len(), 1);
    assert!(alice_groups[0].is_admin);

    assert!(db
        .groups()
        .remove_user(editors.id, bob.id, None)
        .await
        .unwrap());
    assert!(db
        .groups()
        .get_members(editors.id, None)
        .await
        .unwrap()
        .is_empty());

    let updated = db
        .groups()
        .update(
            editors.id,
            GroupUpdate {
                description: Some("New desc".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.description, "New desc");

    assert!(db.groups().delete(editors.id, None).await.unwrap());
}

#[tokio::test]
async fn promote_and_demote_admin() {
    let (db, _dir) = open_test_db().await;
    let _alice = db.users().create("alice", "pw", "", None).await.unwrap(); // admin
    let bob = db.users().create("bob", "pw", "", None).await.unwrap();

    assert!(!db.users().is_admin(bob.id, None).await.unwrap());

    db.users().set_admin(bob.id, true, None).await.unwrap();
    assert!(db.users().is_admin(bob.id, None).await.unwrap());

    db.users().set_admin(bob.id, false, None).await.unwrap();
    assert!(!db.users().is_admin(bob.id, None).await.unwrap());
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
    let alice = db.users().create("alice", "pw", "", None).await.unwrap();
    // alice is the first user → automatically admin
    assert!(db.users().is_admin(alice.id, None).await.unwrap());
}

#[tokio::test]
async fn local_backend_verifies_per_call_token() {
    let (db, _dir) = open_test_db().await;
    let alice = db
        .users()
        .create("alice", "pw", "Alice", None)
        .await
        .unwrap();

    // 有効な JWT を発行して渡せばアクセスできる
    let token = db
        .login("alice", "pw", Duration::from_secs(60))
        .await
        .unwrap()
        .expect("token issued");
    let fetched = db
        .users()
        .get_by_id(alice.id, Some(&token))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.id, alice.id);

    // 不正な JWT はエラーになる
    let err = db
        .users()
        .get_by_id(alice.id, Some("not-a-valid-jwt"))
        .await
        .unwrap_err();
    // Error::Jwt(_) であること
    let msg = err.to_string();
    assert!(msg.contains("jwt"), "expected jwt error, got: {msg}");

    // token: None は従来どおり通る
    let fetched = db.users().get_by_id(alice.id, None).await.unwrap().unwrap();
    assert_eq!(fetched.id, alice.id);
}

#[tokio::test]
async fn local_backend_without_token_manager_rejects_token() {
    // secret_path = None → TokenManager 未設定の local backend
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Database::open_local(&db_path, None::<&std::path::Path>)
        .await
        .unwrap();
    let alice = db
        .users()
        .create("alice", "pw", "Alice", None)
        .await
        .unwrap();

    // token を渡すと MissingTokenManager になる
    let err = db
        .users()
        .get_by_id(alice.id, Some("anything"))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        user_permission_core::Error::MissingTokenManager
    ));

    // None なら従来通り通る
    assert!(db
        .users()
        .get_by_id(alice.id, None)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn local_login_service_and_resolve_principal_classifies_service_token() {
    let (db, _dir) = open_test_db().await;
    let (client, secret) = db
        .service_clients()
        .create("svc", &[SCOPE_USERS_READ.to_string()], None)
        .await
        .unwrap();
    let token = db
        .login_service(&client.client_id, &secret, Duration::from_secs(60))
        .await
        .unwrap()
        .expect("service token");

    match db.resolve_principal(&token).await.unwrap().expect("principal") {
        Principal::Service { client_id, scopes } => {
            assert_eq!(client_id, client.client_id);
            assert_eq!(scopes, vec![SCOPE_USERS_READ.to_string()]);
        }
        other => panic!("expected a service principal, got {other:?}"),
    }

    // A service token must never resolve to a user.
    assert!(db.verify_token_and_get_user(&token).await.unwrap().is_none());

    // Wrong secret is rejected as a failed login.
    assert!(db
        .login_service(&client.client_id, "wrong", Duration::from_secs(60))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn local_resolve_principal_rejects_inactive_user() {
    let (db, _dir) = open_test_db().await;
    let alice = db.users().create("alice", "pw", "", None).await.unwrap();
    let token = db
        .login("alice", "pw", Duration::from_secs(60))
        .await
        .unwrap()
        .expect("token");

    // An active user resolves fine.
    assert!(matches!(
        db.resolve_principal(&token).await.unwrap(),
        Some(Principal::User(_))
    ));

    // Once deactivated, the same (still-valid) token resolves to None.
    db.users()
        .update(
            alice.id,
            UserUpdate {
                is_active: Some(false),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    assert!(db.resolve_principal(&token).await.unwrap().is_none());
}

//! リレー先サーバーの切り替え・すり替わりに対する防御のテスト。
//!
//! 署名鍵 (secret.key) を共有する 2 台のサーバーを別 DB で起動し、
//! 「サーバー A のトークン・ユーザー ID がサーバー B で通用しない」ことを
//! 確認する。iss (server_id) クレームの検証と relay 側の server_id pin が対象。

use std::time::Duration;

use serde_json::Value;
use user_permission::{build_app, WebConfig};
use user_permission_core::{Database, Error};

/// 指定した secret.key を使うサーバーをエフェメラルポートで起動する。
async fn spawn_server_with_secret(
    dir: &tempfile::TempDir,
    name: &str,
    secret_path: &std::path::Path,
) -> String {
    let db = Database::open_local(dir.path().join(format!("{name}.db")), Some(secret_path))
        .await
        .expect("open db");
    // 最初のユーザーは自動で admin になる。両サーバーに同名ユーザーを作る。
    db.users().create("alice", "pw-123456", "Alice", None).await.unwrap();

    let app = build_app(db, WebConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn spawn_two_servers_sharing_secret() -> (String, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.key");
    let base_a = spawn_server_with_secret(&dir, "a", &secret).await;
    let base_b = spawn_server_with_secret(&dir, "b", &secret).await;
    (base_a, base_b, dir)
}

#[tokio::test]
async fn token_from_server_a_is_rejected_by_server_b() {
    let (base_a, base_b, _dir) = spawn_two_servers_sharing_secret().await;
    let client = reqwest::Client::new();

    // サーバー A でログイン。
    let resp = client
        .post(format!("{base_a}/token"))
        .form(&[("username", "alice"), ("password", "pw-123456")])
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    let token_a = body["access_token"].as_str().unwrap().to_string();
    assert!(body["server_id"].as_str().is_some(), "token response carries server_id");

    // A のトークンは A では有効。
    let resp = client
        .get(format!("{base_a}/me"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // 同じ署名鍵でも、B では iss (server_id) 不一致で拒否される。
    let resp = client
        .get(format!("{base_b}/me"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401, "server B must reject server A's token");

    let resp = client
        .post(format!("{base_b}/introspect"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn server_info_exposes_distinct_stable_ids() {
    let (base_a, base_b, _dir) = spawn_two_servers_sharing_secret().await;
    let client = reqwest::Client::new();

    let id_a = client
        .get(format!("{base_a}/server-info"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["server_id"]
        .as_str()
        .unwrap()
        .to_string();
    let id_b = client
        .get(format!("{base_b}/server-info"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["server_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(id_a, id_b, "each server must have its own server_id");

    // 同じサーバーへの再問い合わせでは同じ id が返る。
    let again = client
        .get(format!("{base_a}/server-info"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["server_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(again, id_a);
}

#[tokio::test]
async fn pinned_relay_rejects_switched_server() {
    let (base_a, base_b, _dir) = spawn_two_servers_sharing_secret().await;

    // A に接続して server_id を取得(クライアントはこれを永続化する想定)。
    let relay_a = Database::open_relay(&base_a).unwrap();
    let id_a = relay_a.server_id().await.unwrap();
    assert!(relay_a
        .login("alice", "pw-123456", Duration::from_secs(3600))
        .await
        .unwrap()
        .is_some());

    // 接続先を B に切り替えたが pin は A のまま → ログインは拒否される。
    let relay_switched = Database::open_relay_pinned(&base_b, &id_a).unwrap();
    let err = relay_switched
        .login("alice", "pw-123456", Duration::from_secs(3600))
        .await
        .expect_err("login against a different server must fail");
    match err {
        Error::RelayServerMismatch { expected, actual } => {
            assert_eq!(expected, id_a);
            assert_ne!(actual, id_a);
        }
        other => panic!("expected RelayServerMismatch, got {other:?}"),
    }
    // 不一致検出後は内部トークンを保持しない(認証なしでは introspect も通らない)。
    assert!(relay_switched
        .resolve_principal("not-a-token")
        .await
        .unwrap()
        .is_none());

    // pin が一致していれば通常どおりログインできる。
    let relay_pinned_ok = Database::open_relay_pinned(&base_a, &id_a).unwrap();
    assert!(relay_pinned_ok
        .login("alice", "pw-123456", Duration::from_secs(3600))
        .await
        .unwrap()
        .is_some());
}

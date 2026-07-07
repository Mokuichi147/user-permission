# UserPermission

![Crates.io License](https://img.shields.io/crates/l/user-permission?cacheSeconds=0)
![Crates.io Version](https://img.shields.io/crates/v/user-permission?cacheSeconds=0)

ユーザーとグループを管理するための非同期 Rust ライブラリです。

- **コア (`user-permission-core`)**: tokio + sqlx(SQLite) + argon2 + jsonwebtoken
- **サーバー (`user-permission`)**: axum で実装した REST API ライブラリ + `user-permission` CLI
- **リレー**: ローカル SQLite と中央サーバーを同じインターフェースで切り替え可能

## インストール

```bash
cargo add user-permission-core   # コア (DB / 認証 / JWT) のみ
cargo add user-permission        # axum ルーターを別アプリに組み込む
cargo install user-permission    # 単体サーバーとしてインストール
```

## 使い方

### コアだけ使う (`user-permission-core`)

```rust
use std::time::Duration;
use user_permission_core::Database;

#[tokio::main]
async fn main() -> user_permission_core::Result<()> {
    // パスを渡すとローカル SQLite、URL を渡すと HTTP 中継になる
    let db = Database::open("app.db", Some("secret.key")).await?;

    let alice = db.users().create("alice", "password123", "Alice", None).await?;
    let token = db
        .login("alice", "password123", Duration::from_secs(3600))
        .await?
        .expect("credentials");
    println!("token = {token}");

    let editors = db.groups().create("editors", "Editors", false, None).await?;
    db.groups().add_user(editors.id, alice.id, None).await?;

    Ok(())
}
```

### axum ルーターを別アプリに組み込む (`user-permission`)

```rust
use user_permission::{build_app, WebConfig};
use user_permission_core::Database;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db = Database::open("app.db", Some("secret.key")).await?;
    let app = build_app(db, WebConfig { api_prefix: "/api".into(), ..Default::default() });
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8001").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

### サーバー単体起動 (CLI)

```bash
cargo install user-permission
user-permission serve --host 0.0.0.0 --port 8001 --prefix /api --webui
```

| オプション | デフォルト | 説明 |
|---|---|---|
| `--host` | `127.0.0.1` | バインドアドレス |
| `--port` | `8000` | バインドポート |
| `--database` | `user_permission.db` | SQLiteデータベースのパス |
| `--secret` | `secret.key` | シークレットキーファイルのパス |
| `--prefix` | (なし) | APIルートプレフィックス（例: `/api`） |
| `--webui` | 無効 | Web管理画面（HTMX+Tailwind）を有効化 |
| `--webui-prefix` | `/ui` | 管理画面のURLプレフィックス |

> **Web 管理画面の移植状況**: 現在はプレースホルダ画面のみ提供しています。HTMX/Tailwind ベースの完全な管理画面は今後のリリースで再実装予定です。当面は REST API を利用してください。

### リレー（中継）

`Database::open()` はターゲット文字列の形で backend を自動的に振り分けるので、
ローカル SQLite と中央サーバーを同じインターフェースで切り替えられます。

```rust
use user_permission_core::Database;

// ファイルパス → ローカル SQLite（secret は JWT 署名鍵のパス）
let db = Database::open("app.db", Some("secret.key")).await?;

// URL → リモートサーバーへ HTTP 中継（署名鍵はサーバーが持つため secret は None）
let db = Database::open("http://localhost:8001", None).await?;

// リレー先へログインすると以後のリクエストにトークンが自動付与される
let _token = db.login("alice", "password123", std::time::Duration::from_secs(3600)).await?;
```

backend が確定している場合は `Database::open_local()` / `Database::open_relay()` も使えます。

### ログイン試行のレート制限

ログイン（`POST /token` の password / client_credentials 両グラント、および WebUI の
ログイン）は、同一ユーザー名（またはクライアントID）での連続失敗が
`WebConfig::login_max_failures` 回（デフォルト 5 回）に達すると、
`WebConfig::login_lockout`（デフォルト 5 分）の間 `429 Too Many Requests` で
拒否されます。成功するとカウントはリセットされます。失敗は `tracing` の
warn レベルで記録されます。`login_max_failures: 0` で無効化できます。

カウンタはプロセス内メモリ上にあるため、複数インスタンス構成では
インスタンスごとに独立して数えられる点に注意してください。

## REST API

| メソッド | パス | 説明 | 認証 |
|---|---|---|---|
| POST | `/token` | ログイン（`password` / `client_credentials` grant） | 不要 |
| POST | `/introspect` | トークンを principal（ユーザー / サービス）に解決 | 必要 |
| GET | `/me` | 現在のユーザー情報（`is_admin` を含む） | 必要 |
| POST | `/users` | ユーザー作成 | 不要 |
| GET | `/users` | ユーザー一覧（`?username=...` で username 完全一致検索） | 必要 |
| GET | `/users/{id}` | ユーザー取得 | 必要 |
| PATCH | `/users/{id}` | ユーザー更新 | 本人 or 管理者 |
| DELETE | `/users/{id}` | ユーザー削除 | 本人 or 管理者 |
| POST | `/groups` | グループ作成 | 管理者 |
| GET | `/groups` | グループ一覧 | 必要 |
| GET | `/groups/{id}` | グループ取得 | 必要 |
| PATCH | `/groups/{id}` | グループ更新 | 管理者 |
| DELETE | `/groups/{id}` | グループ削除 | 管理者 |
| POST | `/groups/{id}/members` | メンバー追加 | 管理者 |
| DELETE | `/groups/{id}/members/{user_id}` | メンバー削除 | 管理者 |
| GET | `/groups/{id}/members` | メンバー一覧 | 必要 |
| GET | `/users/{id}/groups` | 所属グループ一覧 | 必要 |
| POST | `/service-clients` | サービスクライアント作成（secret を返却） | 管理者 |
| GET | `/service-clients` | サービスクライアント一覧 | 管理者 |
| DELETE | `/service-clients/{id}` | サービスクライアント削除 | 管理者 |
| POST | `/service-clients/{id}/rotate` | secret の再生成 | 管理者 |

## 管理者ロール

UserPermission サーバー自身の管理権限は `groups.is_admin = 1` のグループで表現します。
このフラグが立った **管理者グループ** に所属しているユーザーが「UserPermission 管理者」です。

- 管理者は他ユーザーの編集・削除、グループの作成・更新・削除、メンバー管理が可能
- 他ユーザーの管理者昇格/降格は、管理者グループへの加入/脱退で行う
- 管理者グループは複数作れる（運用で分けたい場合）
- **消費サービス側の「アプリ管理者」などの概念はこの権限とは別**で、通常のグループ（`is_admin = 0`）で自由に表現してください

### 初回セットアップ

最初に作成されたユーザーは **自動的に管理者グループに加入** します。`admin` という名前のグループが無ければ、`is_admin = 1` で新規作成されます。

### 既存DBのマイグレーション

起動時には `groups.is_admin` 列の存在を確認し、無ければ `ALTER TABLE` で追加します。既存データは壊しません。
v0.2.0 以降で作成された SQLite ファイルはそのまま使えます。

## データベーススキーマ

| テーブル | 説明 |
|---|---|
| `users` | ユーザー情報（`username` は UNIQUE） |
| `groups` | グループ情報（`name` は UNIQUE） |
| `user_groups` | ユーザーとグループの多対多リレーション（複合PRIMARY KEY） |

ユーザーまたはグループを削除すると、関連する `user_groups` レコードも自動的に削除されます（CASCADE）。

## 開発

```bash
cargo test --workspace
cargo build --release
```

## ライセンス

MIT OR Apache-2.0

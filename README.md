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

    let alice = db.users().create("alice", "s3cret-pass", "Alice", None).await?;
    let token = db
        .login("alice", "s3cret-pass", Duration::from_secs(3600))
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
| `--cookie-secure` | 無効 | セッションCookieに `Secure` 属性を付与（HTTPS運用時は必ず有効化） |
| `--password-min-len` | `8` | パスワードの最小文字数 |

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
let _token = db.login("alice", "s3cret-pass", std::time::Duration::from_secs(3600)).await?;
```

backend が確定している場合は `Database::open_local()` / `Database::open_relay()` も使えます。

### ユーザー ID と server_id

ユーザー ID は **UUID v7**(`uuid::Uuid`)です。API・JWT の `sub`・DB 上のすべてで
文字列表現(ハイフン付き36文字)を使います。

各サーバー(=各データベース)は初回起動時に固有の **server_id**(UUID)を生成して
`meta` テーブルに永続化し、発行する JWT の `iss` クレームに埋め込みます。検証時は
`iss` の一致が必須のため、同じ署名鍵を使い回した別サーバーのトークンでも拒否されます。
server_id は認証不要の `GET /server-info` と `POST /token` のレスポンスで取得できます。

リレークライアントは初回応答の server_id を pin し、以後の応答と不一致なら内部トークンを
破棄して `Error::RelayServerMismatch` を返します。接続先の切り替え・すり替わりを確実に
検出したい場合は、取得済みの server_id を永続化して `Database::open_relay_pinned()` に
渡してください。

```rust,ignore
let db = Database::open_relay("http://central:8001")?;
let server_id = db.server_id().await?; // 永続化しておく

// 次回以降: 別サーバーにすり替わっていればログイン時点でエラーになる
let db = Database::open_relay_pinned("http://central:8001", &server_id)?;
```

**旧バージョン(連番 i64 の id)からの移行**: 既存 DB は起動時に自動でテーブルを再構築し、
全ユーザーへ UUID を割り当てます(グループ所属も引き継がれます)。実行前に
`<db>.pre-uuid.bak` へバックアップが作成されます。旧形式の JWT(数値 sub・`iss` なし)は
すべて無効になるため、全ユーザーの再ログインが必要です。旧クライアントと新サーバーの
混在は動作しません。

### トークンの失効

発行済みトークンはユーザーごとの `token_version` 方式で失効できます。JWT には発行時点の
バージョンが `ver` クレームとして埋め込まれ、検証時に DB の現在値と一致しない場合は
無効扱いになります。

- `db.revoke_tokens(user_id)` / `POST /users/{id}/revoke-tokens`（本人または管理者）で、
  そのユーザーの発行済みトークンをすべて失効
- パスワード変更・アカウント無効化・WebUI からのログアウトでも自動的に失効

トレードオフ: 失効の単位はユーザー全体で、トークン個別の失効はできません（ログアウトは
そのユーザーの全セッション・全トークンを無効化します）。検証のたびに SQLite への軽い
参照が1回増えますが、deny-list 方式と違い失効レコードの掃除が不要で、サーバー側に増える
状態はユーザー行の整数1つだけです。

### ログイン試行のレート制限

ログイン（`POST /token` の password / client_credentials 両グラント、および WebUI の
ログイン）は、同一ユーザー名（またはクライアントID）での連続失敗が
`WebConfig::login_max_failures` 回（デフォルト 5 回）に達すると、
`WebConfig::login_lockout`（デフォルト 5 分）の間 `429 Too Many Requests` で
拒否されます。成功するとカウントはリセットされます。失敗は `tracing` の
warn レベルで記録されます。`login_max_failures: 0` で無効化できます。

カウンタはプロセス内メモリ上にあるため、複数インスタンス構成では
インスタンスごとに独立して数えられる点に注意してください。

### パスワードポリシー

パスワードを設定するすべての経路（作成・更新・WebUI の登録／変更／リセット）で、
core 層の共通バリデーションが適用されます。

- 最小長は既定 8文字（`MIN_PASSWORD_LEN`）、`PasswordPolicy` で変更可能
- 1024バイト以下（`MAX_PASSWORD_LEN`、こちらは固定の安全上限で変更不可）
- `password` や `12345678` などのよくあるパスワードは長さを満たしても拒否

違反時は `Error::WeakPassword`（REST API では `400 Bad Request`）が返ります。
`user_permission_core::validate_password()` で既定ポリシーの事前チェックもできます。

最小長を変えたい場合は `Database::open_local_with_policy()` に `PasswordPolicy` を渡します。

```rust
use user_permission_core::{Database, PasswordPolicy};

let policy = PasswordPolicy { min_len: 12 };
let db = Database::open_local_with_policy("app.db", Some("secret.key"), policy).await?;
```

CLI サーバーでは `--password-min-len`（既定 8）で指定できます。

```bash
user-permission serve --password-min-len 12
```

リレー backend ではポリシーは中央サーバー側が権威を持ち、クライアント側では
チェックしません（サーバーの `POST /users` / `PATCH /users/{id}` が拒否します）。

## REST API

| メソッド | パス | 説明 | 認証 |
|---|---|---|---|
| POST | `/token` | ログイン（`password` / `client_credentials` grant）。`server_id` を含む | 不要 |
| POST | `/introspect` | トークンを principal（ユーザー / サービス）に解決。`{server_id, principal}` を返す | 必要 |
| GET | `/server-info` | サーバー識別子（`server_id`）を返す | 不要 |
| GET | `/me` | 現在のユーザー情報（`is_admin` を含む） | 必要 |
| POST | `/users` | ユーザー作成 | 不要 |
| GET | `/users` | ユーザー一覧（`?username=...` で username 完全一致検索） | 必要※ |
| GET | `/users/{id}` | ユーザー取得 | 本人 or 管理者※ |
| PATCH | `/users/{id}` | ユーザー更新 | 本人 or 管理者 |
| DELETE | `/users/{id}` | ユーザー削除 | 本人 or 管理者 |
| POST | `/users/{id}/revoke-tokens` | 発行済みトークンを全失効 | 本人 or 管理者 |
| POST | `/groups` | グループ作成 | 管理者 |
| GET | `/groups` | グループ一覧 | 必要※ |
| GET | `/groups/{id}` | グループ取得 | 所属メンバー or 管理者※ |
| PATCH | `/groups/{id}` | グループ更新 | 管理者 |
| DELETE | `/groups/{id}` | グループ削除 | 管理者 |
| POST | `/groups/{id}/members` | メンバー追加 | 管理者 |
| DELETE | `/groups/{id}/members/{user_id}` | メンバー削除 | 管理者 |
| GET | `/groups/{id}/members` | メンバー一覧 | 所属メンバー or 管理者※ |
| GET | `/users/{id}/groups` | 所属グループ一覧 | 本人 or 管理者※ |
| POST | `/service-clients` | サービスクライアント作成（secret を返却） | 管理者 |
| GET | `/service-clients` | サービスクライアント一覧 | 管理者 |
| DELETE | `/service-clients/{id}` | サービスクライアント削除 | 管理者 |
| POST | `/service-clients/{id}/rotate` | secret の再生成 | 管理者 |

### 閲覧範囲（最小権限）

※ の付いた読み取り系エンドポイントには次のポリシーが適用されます。

- **一般ユーザー**: 閲覧できるのは自分自身と自分の所属グループのみ。
  `GET /users` は自分1件だけを返し、他ユーザー・非所属グループへのアクセスは
  `403 Forbidden` になります（WebUI も同様で、ユーザー一覧は管理者専用）
- **管理者**: ディレクトリ全体を閲覧可能
- **サービストークン**: `users:read` / `groups:read` スコープを持つ
  client_credentials トークンはディレクトリ全体を閲覧可能。アプリケーションから
  ユーザー基盤全体を参照したい場合はこちらを使ってください

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

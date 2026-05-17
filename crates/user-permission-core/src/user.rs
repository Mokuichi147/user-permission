use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::Row;

use crate::database::Backend;
use crate::error::{Error, Result};
use crate::password::{hash, verify};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl User {
    fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            display_name: row.try_get("display_name")?,
            is_active: row.try_get::<i64, _>("is_active")? != 0,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Default)]
pub struct UserUpdate {
    pub username: Option<String>,
    pub password: Option<String>,
    pub display_name: Option<String>,
    pub is_active: Option<bool>,
}

pub struct UserManager {
    backend: Arc<Backend>,
}

impl UserManager {
    pub(crate) fn new(backend: Arc<Backend>) -> Self {
        Self { backend }
    }

    pub async fn create(
        &self,
        username: &str,
        password: &str,
        display_name: &str,
    ) -> Result<User> {
        match &*self.backend {
            Backend::Local(local) => {
                let pool = &local.pool;
                let hashed = hash(password)?;

                let mut tx = pool.begin().await?;

                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
                    .fetch_one(&mut *tx)
                    .await?;
                let is_first = count == 0;

                let row = sqlx::query(
                    "INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?) RETURNING *",
                )
                .bind(username)
                .bind(&hashed)
                .bind(display_name)
                .fetch_one(&mut *tx)
                .await
                .map_err(map_unique_error)?;

                let user = User::from_row(&row)?;

                if is_first {
                    let existing: Option<(i64,)> =
                        sqlx::query_as("SELECT id FROM groups WHERE name = ?")
                            .bind("admin")
                            .fetch_optional(&mut *tx)
                            .await?;
                    let admin_group_id = if let Some((id,)) = existing {
                        sqlx::query("UPDATE groups SET is_admin = 1 WHERE id = ?")
                            .bind(id)
                            .execute(&mut *tx)
                            .await?;
                        id
                    } else {
                        let (id,): (i64,) = sqlx::query_as(
                            "INSERT INTO groups (name, description, is_admin) VALUES (?, ?, 1) RETURNING id",
                        )
                        .bind("admin")
                        .bind("UserPermission 管理者")
                        .fetch_one(&mut *tx)
                        .await?;
                        id
                    };

                    sqlx::query(
                        "INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
                    )
                    .bind(user.id)
                    .bind(admin_group_id)
                    .execute(&mut *tx)
                    .await?;
                }

                tx.commit().await?;
                Ok(user)
            }
            Backend::Relay(relay) => {
                let body = serde_json::json!({
                    "username": username,
                    "password": password,
                    "display_name": display_name,
                });
                relay.request_json("POST", "/users", Some(body), false).await
            }
        }
    }

    pub async fn get_by_id(&self, user_id: i64) -> Result<Option<User>> {
        match &*self.backend {
            Backend::Local(local) => {
                let row = sqlx::query("SELECT * FROM users WHERE id = ?")
                    .bind(user_id)
                    .fetch_optional(&local.pool)
                    .await?;
                row.as_ref().map(User::from_row).transpose()
            }
            Backend::Relay(relay) => relay
                .request_json_opt("GET", &format!("/users/{user_id}"), None, true)
                .await,
        }
    }

    pub async fn get_by_username(&self, username: &str) -> Result<Option<User>> {
        match &*self.backend {
            Backend::Local(local) => {
                let row = sqlx::query("SELECT * FROM users WHERE username = ?")
                    .bind(username)
                    .fetch_optional(&local.pool)
                    .await?;
                row.as_ref().map(User::from_row).transpose()
            }
            Backend::Relay(_) => Err(Error::InvalidArgument(
                "get_by_username is not supported over the relay backend".into(),
            )),
        }
    }

    pub async fn list_all(&self) -> Result<Vec<User>> {
        match &*self.backend {
            Backend::Local(local) => {
                let rows = sqlx::query("SELECT * FROM users ORDER BY id")
                    .fetch_all(&local.pool)
                    .await?;
                rows.iter().map(User::from_row).collect()
            }
            Backend::Relay(relay) => {
                let users: Vec<User> = relay.request_json("GET", "/users", None, true).await?;
                Ok(users)
            }
        }
    }

    pub async fn update(&self, user_id: i64, update: UserUpdate) -> Result<Option<User>> {
        match &*self.backend {
            Backend::Local(local) => {
                let pool = &local.pool;
                let mut fields: Vec<&str> = Vec::new();
                let mut params: Vec<Value> = Vec::new();

                if let Some(u) = &update.username {
                    fields.push("username = ?");
                    params.push(Value::String(u.clone()));
                }
                if let Some(p) = &update.password {
                    fields.push("password_hash = ?");
                    params.push(Value::String(hash(p)?));
                }
                if let Some(d) = &update.display_name {
                    fields.push("display_name = ?");
                    params.push(Value::String(d.clone()));
                }
                if let Some(a) = update.is_active {
                    fields.push("is_active = ?");
                    params.push(Value::Number((a as i64).into()));
                }
                if fields.is_empty() {
                    return self.get_by_id(user_id).await;
                }
                fields.push("updated_at = datetime('now')");
                let sql = format!(
                    "UPDATE users SET {} WHERE id = ?",
                    fields.join(", ")
                );
                let mut q = sqlx::query(&sql);
                for p in &params {
                    q = match p {
                        Value::String(s) => q.bind(s.clone()),
                        Value::Number(n) => q.bind(n.as_i64().unwrap_or(0)),
                        _ => q,
                    };
                }
                q = q.bind(user_id);
                q.execute(pool).await.map_err(map_unique_error)?;
                self.get_by_id(user_id).await
            }
            Backend::Relay(relay) => {
                let mut body = Map::new();
                if let Some(u) = update.username {
                    body.insert("username".into(), Value::String(u));
                }
                if let Some(p) = update.password {
                    body.insert("password".into(), Value::String(p));
                }
                if let Some(d) = update.display_name {
                    body.insert("display_name".into(), Value::String(d));
                }
                if let Some(a) = update.is_active {
                    body.insert("is_active".into(), Value::Bool(a));
                }
                relay
                    .request_json_opt(
                        "PATCH",
                        &format!("/users/{user_id}"),
                        Some(Value::Object(body)),
                        true,
                    )
                    .await
            }
        }
    }

    pub async fn delete(&self, user_id: i64) -> Result<bool> {
        match &*self.backend {
            Backend::Local(local) => {
                let res = sqlx::query("DELETE FROM users WHERE id = ?")
                    .bind(user_id)
                    .execute(&local.pool)
                    .await?;
                Ok(res.rows_affected() > 0)
            }
            Backend::Relay(relay) => relay
                .request_no_content("DELETE", &format!("/users/{user_id}"), None, true)
                .await,
        }
    }

    pub async fn is_admin(&self, user_id: i64) -> Result<bool> {
        match &*self.backend {
            Backend::Local(local) => {
                let row = sqlx::query(
                    "SELECT 1 AS one FROM user_groups ug \
                     JOIN groups g ON ug.group_id = g.id \
                     WHERE ug.user_id = ? AND g.is_admin = 1 \
                     LIMIT 1",
                )
                .bind(user_id)
                .fetch_optional(&local.pool)
                .await?;
                Ok(row.is_some())
            }
            Backend::Relay(relay) => {
                let user: Value = relay
                    .request_json("GET", &format!("/users/{user_id}"), None, true)
                    .await?;
                Ok(user.get("is_admin").and_then(Value::as_bool).unwrap_or(false))
            }
        }
    }

    /// Promote or demote a user by joining/leaving an admin group.
    pub async fn set_admin(&self, user_id: i64, is_admin: bool) -> Result<bool> {
        let local = self.backend.as_local()?;
        let pool = &local.pool;
        let mut tx = pool.begin().await?;

        if is_admin {
            let group_id: Option<(i64,)> = sqlx::query_as(
                "SELECT id FROM groups WHERE name = ? AND is_admin = 1",
            )
            .bind("admin")
            .fetch_optional(&mut *tx)
            .await?;
            let group_id = if let Some((id,)) = group_id {
                id
            } else {
                let row: Option<(i64,)> = sqlx::query_as(
                    "SELECT id FROM groups WHERE is_admin = 1 ORDER BY id LIMIT 1",
                )
                .fetch_optional(&mut *tx)
                .await?;
                if let Some((id,)) = row {
                    id
                } else {
                    let (id,): (i64,) = sqlx::query_as(
                        "INSERT INTO groups (name, description, is_admin) VALUES (?, ?, 1) RETURNING id",
                    )
                    .bind("admin")
                    .bind("UserPermission 管理者")
                    .fetch_one(&mut *tx)
                    .await?;
                    id
                }
            };
            sqlx::query("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)")
                .bind(user_id)
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query(
                "DELETE FROM user_groups \
                 WHERE user_id = ? \
                   AND group_id IN (SELECT id FROM groups WHERE is_admin = 1)",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(true)
    }

    /// Verify credentials and return a freshly issued JWT (local backend only).
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        expires_in: Duration,
    ) -> Result<Option<String>> {
        match &*self.backend {
            Backend::Local(local) => {
                let token_manager = local
                    .token_manager
                    .as_ref()
                    .ok_or(Error::MissingTokenManager)?;
                let row = sqlx::query(
                    "SELECT * FROM users WHERE username = ? AND is_active = 1",
                )
                .bind(username)
                .fetch_optional(&local.pool)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                let stored_hash: String = row.try_get("password_hash")?;
                if !verify(password, &stored_hash) {
                    return Ok(None);
                }
                let user = User::from_row(&row)?;
                let is_admin = self.is_admin(user.id).await?;
                let mut extra = Map::new();
                extra.insert("is_admin".into(), Value::Bool(is_admin));
                let token = token_manager.create_token(
                    user.id,
                    &user.username,
                    expires_in,
                    Some(&extra),
                )?;
                Ok(Some(token))
            }
            Backend::Relay(relay) => {
                let token = relay.login(username, password).await?;
                Ok(Some(token))
            }
        }
    }
}

fn map_unique_error(err: sqlx::Error) -> Error {
    if let sqlx::Error::Database(ref db_err) = err {
        if db_err
            .code()
            .map(|c| c == "2067" || c == "1555")
            .unwrap_or(false)
        {
            return Error::Conflict("UNIQUE constraint failed".into());
        }
    }
    Error::Db(err)
}

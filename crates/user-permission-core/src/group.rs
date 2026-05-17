use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::Row;

use crate::database::Backend;
use crate::error::{Error, Result};
use crate::user::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub is_admin: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl Group {
    fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            is_admin: row.try_get::<i64, _>("is_admin")? != 0,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Default)]
pub struct GroupUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_admin: Option<bool>,
}

pub struct GroupManager {
    backend: Arc<Backend>,
}

impl GroupManager {
    pub(crate) fn new(backend: Arc<Backend>) -> Self {
        Self { backend }
    }

    pub async fn create(
        &self,
        name: &str,
        description: &str,
        is_admin: bool,
    ) -> Result<Group> {
        match &*self.backend {
            Backend::Local(local) => {
                let row = sqlx::query(
                    "INSERT INTO groups (name, description, is_admin) VALUES (?, ?, ?) RETURNING *",
                )
                .bind(name)
                .bind(description)
                .bind(is_admin as i64)
                .fetch_one(&local.pool)
                .await
                .map_err(|e| {
                    if let sqlx::Error::Database(ref db_err) = e {
                        if db_err
                            .code()
                            .map(|c| c == "2067" || c == "1555")
                            .unwrap_or(false)
                        {
                            return Error::Conflict("group name already exists".into());
                        }
                    }
                    Error::Db(e)
                })?;
                Group::from_row(&row)
            }
            Backend::Relay(relay) => {
                let body = serde_json::json!({
                    "name": name,
                    "description": description,
                    "is_admin": is_admin,
                });
                relay.request_json("POST", "/groups", Some(body), true).await
            }
        }
    }

    pub async fn get_by_id(&self, group_id: i64) -> Result<Option<Group>> {
        match &*self.backend {
            Backend::Local(local) => {
                let row = sqlx::query("SELECT * FROM groups WHERE id = ?")
                    .bind(group_id)
                    .fetch_optional(&local.pool)
                    .await?;
                row.as_ref().map(Group::from_row).transpose()
            }
            Backend::Relay(relay) => relay
                .request_json_opt("GET", &format!("/groups/{group_id}"), None, true)
                .await,
        }
    }

    pub async fn get_by_name(&self, name: &str) -> Result<Option<Group>> {
        match &*self.backend {
            Backend::Local(local) => {
                let row = sqlx::query("SELECT * FROM groups WHERE name = ?")
                    .bind(name)
                    .fetch_optional(&local.pool)
                    .await?;
                row.as_ref().map(Group::from_row).transpose()
            }
            Backend::Relay(_) => Err(Error::InvalidArgument(
                "get_by_name is not supported over the relay backend".into(),
            )),
        }
    }

    pub async fn list_all(&self) -> Result<Vec<Group>> {
        match &*self.backend {
            Backend::Local(local) => {
                let rows = sqlx::query("SELECT * FROM groups ORDER BY id")
                    .fetch_all(&local.pool)
                    .await?;
                rows.iter().map(Group::from_row).collect()
            }
            Backend::Relay(relay) => {
                relay.request_json("GET", "/groups", None, true).await
            }
        }
    }

    pub async fn list_admin_groups(&self) -> Result<Vec<Group>> {
        let local = self.backend.as_local()?;
        let rows = sqlx::query("SELECT * FROM groups WHERE is_admin = 1 ORDER BY id")
            .fetch_all(&local.pool)
            .await?;
        rows.iter().map(Group::from_row).collect()
    }

    pub async fn update(&self, group_id: i64, update: GroupUpdate) -> Result<Option<Group>> {
        match &*self.backend {
            Backend::Local(local) => {
                let mut fields: Vec<&str> = Vec::new();
                let mut params: Vec<Value> = Vec::new();
                if let Some(n) = &update.name {
                    fields.push("name = ?");
                    params.push(Value::String(n.clone()));
                }
                if let Some(d) = &update.description {
                    fields.push("description = ?");
                    params.push(Value::String(d.clone()));
                }
                if let Some(a) = update.is_admin {
                    fields.push("is_admin = ?");
                    params.push(Value::Number((a as i64).into()));
                }
                if fields.is_empty() {
                    return self.get_by_id(group_id).await;
                }
                fields.push("updated_at = datetime('now')");
                let sql = format!(
                    "UPDATE groups SET {} WHERE id = ?",
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
                q = q.bind(group_id);
                q.execute(&local.pool).await?;
                self.get_by_id(group_id).await
            }
            Backend::Relay(relay) => {
                let mut body = Map::new();
                if let Some(n) = update.name {
                    body.insert("name".into(), Value::String(n));
                }
                if let Some(d) = update.description {
                    body.insert("description".into(), Value::String(d));
                }
                if let Some(a) = update.is_admin {
                    body.insert("is_admin".into(), Value::Bool(a));
                }
                relay
                    .request_json_opt(
                        "PATCH",
                        &format!("/groups/{group_id}"),
                        Some(Value::Object(body)),
                        true,
                    )
                    .await
            }
        }
    }

    pub async fn delete(&self, group_id: i64) -> Result<bool> {
        match &*self.backend {
            Backend::Local(local) => {
                let res = sqlx::query("DELETE FROM groups WHERE id = ?")
                    .bind(group_id)
                    .execute(&local.pool)
                    .await?;
                Ok(res.rows_affected() > 0)
            }
            Backend::Relay(relay) => relay
                .request_no_content("DELETE", &format!("/groups/{group_id}"), None, true)
                .await,
        }
    }

    pub async fn add_user(&self, group_id: i64, user_id: i64) -> Result<bool> {
        match &*self.backend {
            Backend::Local(local) => {
                let res = sqlx::query(
                    "INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
                )
                .bind(user_id)
                .bind(group_id)
                .execute(&local.pool)
                .await;
                Ok(res.is_ok())
            }
            Backend::Relay(relay) => {
                let body = serde_json::json!({"group_id": group_id, "user_id": user_id});
                relay
                    .request_no_content_strict(
                        "POST",
                        &format!("/groups/{group_id}/members"),
                        Some(body),
                        true,
                        201,
                    )
                    .await
            }
        }
    }

    pub async fn remove_user(&self, group_id: i64, user_id: i64) -> Result<bool> {
        match &*self.backend {
            Backend::Local(local) => {
                let res = sqlx::query(
                    "DELETE FROM user_groups WHERE user_id = ? AND group_id = ?",
                )
                .bind(user_id)
                .bind(group_id)
                .execute(&local.pool)
                .await?;
                Ok(res.rows_affected() > 0)
            }
            Backend::Relay(relay) => relay
                .request_no_content(
                    "DELETE",
                    &format!("/groups/{group_id}/members/{user_id}"),
                    None,
                    true,
                )
                .await,
        }
    }

    pub async fn get_members(&self, group_id: i64) -> Result<Vec<User>> {
        match &*self.backend {
            Backend::Local(local) => {
                let rows = sqlx::query(
                    "SELECT u.* FROM users u \
                     JOIN user_groups ug ON u.id = ug.user_id \
                     WHERE ug.group_id = ? \
                     ORDER BY u.id",
                )
                .bind(group_id)
                .fetch_all(&local.pool)
                .await?;
                rows.iter()
                    .map(|row| {
                        Ok::<User, Error>(User {
                            id: row.try_get("id")?,
                            username: row.try_get("username")?,
                            display_name: row.try_get("display_name")?,
                            is_active: row.try_get::<i64, _>("is_active")? != 0,
                            created_at: row.try_get("created_at")?,
                            updated_at: row.try_get("updated_at")?,
                        })
                    })
                    .collect()
            }
            Backend::Relay(relay) => relay
                .request_json("GET", &format!("/groups/{group_id}/members"), None, true)
                .await,
        }
    }

    pub async fn get_user_groups(&self, user_id: i64) -> Result<Vec<Group>> {
        match &*self.backend {
            Backend::Local(local) => {
                let rows = sqlx::query(
                    "SELECT g.* FROM groups g \
                     JOIN user_groups ug ON g.id = ug.group_id \
                     WHERE ug.user_id = ? \
                     ORDER BY g.id",
                )
                .bind(user_id)
                .fetch_all(&local.pool)
                .await?;
                rows.iter().map(Group::from_row).collect()
            }
            Backend::Relay(relay) => relay
                .request_json("GET", &format!("/users/{user_id}/groups"), None, true)
                .await,
        }
    }
}

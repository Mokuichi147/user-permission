use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::database::Backend;
use crate::error::{Error, Result};
use crate::password::{hash, verify};

/// Read-only scope over the user directory.
pub const SCOPE_USERS_READ: &str = "users:read";
/// Read-only scope over groups and membership.
pub const SCOPE_GROUPS_READ: &str = "groups:read";

/// Every scope a service client may be granted. There are deliberately no
/// write or admin scopes: a service token can never mutate state.
pub const ALL_SCOPES: &[&str] = &[SCOPE_USERS_READ, SCOPE_GROUPS_READ];

const CLIENT_ID_PREFIX: &str = "svc_";
const SECRET_PREFIX: &str = "ups_";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceClient {
    pub id: i64,
    pub client_id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

impl ServiceClient {
    fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Self> {
        let scopes: String = row.try_get("scopes")?;
        Ok(Self {
            id: row.try_get("id")?,
            client_id: row.try_get("client_id")?,
            name: row.try_get("name")?,
            scopes: scopes.split_whitespace().map(str::to_string).collect(),
            is_active: row.try_get::<i64, _>("is_active")? != 0,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
        })
    }
}

/// Reject any scope that is not part of [`ALL_SCOPES`]. This is what guarantees
/// a service client can never request a write/admin capability.
pub fn validate_scopes(scopes: &[String]) -> Result<()> {
    for s in scopes {
        if !ALL_SCOPES.contains(&s.as_str()) {
            return Err(Error::InvalidArgument(format!("unknown scope: {s}")));
        }
    }
    Ok(())
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Manager for machine-to-machine service clients. Local backend only: clients
/// are administered directly against SQLite (the relay backend authenticates
/// with an already-issued credential via
/// [`Database::login_client_credentials`](crate::Database::login_client_credentials)).
pub struct ServiceClientManager {
    backend: Arc<Backend>,
}

impl ServiceClientManager {
    pub(crate) fn new(backend: Arc<Backend>) -> Self {
        Self { backend }
    }

    /// Create a new service client. Returns the stored record plus the freshly
    /// generated plaintext secret, which is only ever available here — the
    /// database stores an Argon2 hash.
    pub async fn create(
        &self,
        name: &str,
        scopes: &[String],
        expires_at: Option<&str>,
    ) -> Result<(ServiceClient, String)> {
        validate_scopes(scopes)?;
        let local = self.backend.as_local()?;

        let client_id = format!("{CLIENT_ID_PREFIX}{}", random_hex(12));
        let secret = format!("{SECRET_PREFIX}{}", random_hex(32));
        let secret_hash = hash(&secret)?;
        let scope_str = scopes.join(" ");

        let row = sqlx::query(
            "INSERT INTO service_clients (client_id, secret_hash, name, scopes, expires_at) \
             VALUES (?, ?, ?, ?, ?) RETURNING *",
        )
        .bind(&client_id)
        .bind(&secret_hash)
        .bind(name)
        .bind(&scope_str)
        .bind(expires_at)
        .fetch_one(&local.pool)
        .await?;

        Ok((ServiceClient::from_row(&row)?, secret))
    }

    pub async fn list(&self) -> Result<Vec<ServiceClient>> {
        let local = self.backend.as_local()?;
        let rows = sqlx::query("SELECT * FROM service_clients ORDER BY id")
            .fetch_all(&local.pool)
            .await?;
        rows.iter().map(ServiceClient::from_row).collect()
    }

    pub async fn get_by_client_id(&self, client_id: &str) -> Result<Option<ServiceClient>> {
        let local = self.backend.as_local()?;
        let row = sqlx::query("SELECT * FROM service_clients WHERE client_id = ?")
            .bind(client_id)
            .fetch_optional(&local.pool)
            .await?;
        row.as_ref().map(ServiceClient::from_row).transpose()
    }

    /// Revoke a client by deleting it. Already-issued tokens remain valid until
    /// they expire, but no new tokens can be obtained.
    pub async fn delete(&self, id: i64) -> Result<bool> {
        let local = self.backend.as_local()?;
        let res = sqlx::query("DELETE FROM service_clients WHERE id = ?")
            .bind(id)
            .execute(&local.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Replace a client's secret, returning the new plaintext secret. Returns
    /// `None` if no client with `id` exists.
    pub async fn rotate_secret(&self, id: i64) -> Result<Option<String>> {
        let local = self.backend.as_local()?;
        let secret = format!("{SECRET_PREFIX}{}", random_hex(32));
        let secret_hash = hash(&secret)?;
        let res = sqlx::query("UPDATE service_clients SET secret_hash = ? WHERE id = ?")
            .bind(&secret_hash)
            .bind(id)
            .execute(&local.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Ok(None);
        }
        Ok(Some(secret))
    }

    /// Verify a client_id/secret pair and, on success, issue a short-lived
    /// scoped service JWT. Returns `None` if the client is unknown, inactive,
    /// expired, or the secret does not match.
    pub async fn authenticate(
        &self,
        client_id: &str,
        secret: &str,
        expires_in: Duration,
    ) -> Result<Option<String>> {
        let local = self.backend.as_local()?;
        let token_manager = local
            .token_manager
            .as_ref()
            .ok_or(Error::MissingTokenManager)?;

        let Some(client) = self.get_by_client_id(client_id).await? else {
            return Ok(None);
        };
        if !client.is_active {
            return Ok(None);
        }
        if let Some(expires_at) = &client.expires_at {
            if let Ok(exp) = DateTime::parse_from_rfc3339(expires_at)
                .map(|d| d.with_timezone(&Utc))
                .or_else(|_| {
                    chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
                        .map(|n| n.and_utc())
                })
            {
                if Utc::now() >= exp {
                    return Ok(None);
                }
            }
        }

        let row = sqlx::query("SELECT secret_hash FROM service_clients WHERE id = ?")
            .bind(client.id)
            .fetch_one(&local.pool)
            .await?;
        let stored_hash: String = row.try_get("secret_hash")?;
        if !verify(secret, &stored_hash) {
            return Ok(None);
        }

        sqlx::query("UPDATE service_clients SET last_used_at = datetime('now') WHERE id = ?")
            .bind(client.id)
            .execute(&local.pool)
            .await?;

        let token =
            token_manager.create_service_token(client_id, &client.scopes, expires_in)?;
        Ok(Some(token))
    }
}

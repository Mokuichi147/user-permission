use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use serde_json::{Map, Value};
use std::sync::Arc;
use user_permission_core::{User, SCOPE_GROUPS_READ, SCOPE_USERS_READ};

use crate::error::ApiError;
use crate::state::AppState;

/// Bearer-token authentication extractor. Resolves to the current `User` by
/// verifying the JWT and looking the user up in the database. Service tokens
/// (machine-to-machine clients) are rejected — they have no backing user.
pub struct AuthUser(pub User);

/// Like `AuthUser` but additionally enforces that the user is in an admin group.
pub struct AdminUser(pub User);

/// The authenticated caller: either a human `User` or a scoped service client.
pub enum Principal {
    User(User),
    Service {
        #[allow(dead_code)]
        client_id: String,
        scopes: Vec<String>,
    },
}

/// Read access to the user directory: any authenticated user, or a service
/// client holding the `users:read` scope.
pub struct UsersRead(#[allow(dead_code)] pub Principal);

/// Read access to groups and membership: any authenticated user, or a service
/// client holding the `groups:read` scope.
pub struct GroupsRead(#[allow(dead_code)] pub Principal);

const COOKIE_NAME: &str = "up_token";

fn extract_token(parts: &Parts) -> Option<String> {
    if let Some(value) = parts.headers.get(header::AUTHORIZATION) {
        if let Ok(s) = value.to_str() {
            if let Some(stripped) = s.strip_prefix("Bearer ") {
                return Some(stripped.trim().to_string());
            }
        }
    }
    // Cookie-based auth (webui).
    if let Some(value) = parts.headers.get(header::COOKIE) {
        if let Ok(cookies) = value.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(val) = cookie.strip_prefix(&format!("{COOKIE_NAME}=")) {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

fn decode_claims(state: &Arc<AppState>, token: &str) -> Result<Map<String, Value>, ApiError> {
    state
        .db
        .token_manager()
        .map_err(|_| ApiError::unauthorized("token manager not configured"))?
        .verify_token(token)
        .map_err(|_| ApiError::unauthorized("invalid or expired token"))
}

fn is_service_claims(claims: &Map<String, Value>) -> bool {
    claims.get("kind").and_then(Value::as_str) == Some("service")
}

async fn user_from_claims(
    state: &Arc<AppState>,
    claims: &Map<String, Value>,
) -> Result<User, ApiError> {
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::unauthorized("malformed token"))?;
    let user_id: i64 = sub
        .parse()
        .map_err(|_| ApiError::unauthorized("malformed token sub"))?;
    let user = state
        .db
        .users()
        .get_by_id(user_id, None)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("user not found"))?;
    if !user.is_active {
        return Err(ApiError::unauthorized("user inactive"));
    }
    Ok(user)
}

async fn resolve_user(state: &Arc<AppState>, token: &str) -> Result<User, ApiError> {
    let claims = decode_claims(state, token)?;
    if is_service_claims(&claims) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "service token cannot act as a user",
        ));
    }
    user_from_claims(state, &claims).await
}

async fn resolve_principal(state: &Arc<AppState>, token: &str) -> Result<Principal, ApiError> {
    let claims = decode_claims(state, token)?;
    if is_service_claims(&claims) {
        let client_id = claims
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let scopes = claims
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        Ok(Principal::Service { client_id, scopes })
    } else {
        Ok(Principal::User(user_from_claims(state, &claims).await?))
    }
}

/// Resolve the caller and require `scope` if it is a service client. Users are
/// always allowed read access.
async fn authorize_scope(
    parts: &mut Parts,
    state: &Arc<AppState>,
    scope: &str,
) -> Result<Principal, ApiError> {
    let token = extract_token(parts)
        .ok_or_else(|| ApiError::unauthorized("missing token"))
        .map_err(|e| e.with_bearer())?;
    let principal = resolve_principal(state, &token).await?;
    match &principal {
        Principal::User(_) => Ok(principal),
        Principal::Service { scopes, .. } => {
            if scopes.iter().any(|s| s == scope) {
                Ok(principal)
            } else {
                Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    format!("missing required scope: {scope}"),
                ))
            }
        }
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_token(parts)
            .ok_or_else(|| ApiError::unauthorized("missing token"))
            .map_err(|e| e.with_bearer())?;
        let user = resolve_user(state, &token).await?;
        Ok(AuthUser(user))
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_token(parts)
            .ok_or_else(|| ApiError::unauthorized("missing token"))
            .map_err(|e| e.with_bearer())?;
        let user = resolve_user(state, &token).await?;
        let is_admin = state
            .db
            .users()
            .is_admin(user.id, None)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        if !is_admin {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Admin privileges required",
            ));
        }
        Ok(AdminUser(user))
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for UsersRead {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        Ok(UsersRead(
            authorize_scope(parts, state, SCOPE_USERS_READ).await?,
        ))
    }
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for GroupsRead {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        Ok(GroupsRead(
            authorize_scope(parts, state, SCOPE_GROUPS_READ).await?,
        ))
    }
}

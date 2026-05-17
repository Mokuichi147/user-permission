use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use std::sync::Arc;
use user_permission_core::User;

use crate::error::ApiError;
use crate::state::AppState;

/// Bearer-token authentication extractor. Resolves to the current `User` by
/// verifying the JWT and looking the user up in the database.
pub struct AuthUser(pub User);

/// Like `AuthUser` but additionally enforces that the user is in an admin group.
pub struct AdminUser(pub User);

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

async fn resolve_user(state: &Arc<AppState>, token: &str) -> Result<User, ApiError> {
    let claims = state
        .db
        .token_manager()
        .map_err(|_| ApiError::unauthorized("token manager not configured"))?
        .verify_token(token)
        .map_err(|_| ApiError::unauthorized("invalid or expired token"))?;
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
        .get_by_id(user_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("user not found"))?;
    if !user.is_active {
        return Err(ApiError::unauthorized("user inactive"));
    }
    Ok(user)
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
            .is_admin(user.id)
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

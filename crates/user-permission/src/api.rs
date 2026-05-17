use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use user_permission_core::{GroupUpdate, User, UserUpdate};

use crate::auth::{AdminUser, AuthUser};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
    pub is_admin: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl UserResponse {
    fn from_user(user: User, is_admin: bool) -> Self {
        Self {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            is_active: user.is_active,
            is_admin,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[derive(Serialize)]
pub struct GroupResponse {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub is_admin: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<user_permission_core::Group> for GroupResponse {
    fn from(g: user_permission_core::Group) -> Self {
        Self {
            id: g.id,
            name: g.name,
            description: g.description,
            is_admin: g.is_admin,
            created_at: g.created_at,
            updated_at: g.updated_at,
        }
    }
}

#[derive(Deserialize)]
pub struct UserCreate {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct UserPatch {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub is_active: Option<bool>,
}

#[derive(Deserialize)]
pub struct GroupCreate {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub is_admin: bool,
}

#[derive(Deserialize)]
pub struct GroupPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_admin: Option<bool>,
}

#[derive(Deserialize)]
pub struct GroupMember {
    pub group_id: i64,
    pub user_id: i64,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/token", post(login))
        .route("/me", get(me))
        .route("/users", post(create_user).get(list_users))
        .route(
            "/users/:user_id",
            get(get_user).patch(update_user).delete(delete_user),
        )
        .route("/users/:user_id/groups", get(list_user_groups))
        .route("/groups", post(create_group).get(list_groups))
        .route(
            "/groups/:group_id",
            get(get_group).patch(update_group).delete(delete_group),
        )
        .route(
            "/groups/:group_id/members",
            post(add_member).get(list_members),
        )
        .route(
            "/groups/:group_id/members/:user_id",
            delete(remove_member),
        )
}

async fn login(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Result<Json<TokenResponse>, ApiError> {
    let token = state
        .db
        .users()
        .authenticate(&form.username, &form.password, state.config.token_expires)
        .await?
        .ok_or_else(|| {
            ApiError::unauthorized("Invalid username or password")
        })?;
    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "bearer",
    }))
}

async fn me(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
) -> Result<Json<UserResponse>, ApiError> {
    let is_admin = state.db.users().is_admin(user.id).await?;
    Ok(Json(UserResponse::from_user(user, is_admin)))
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UserCreate>,
) -> Result<(StatusCode, Json<UserResponse>), ApiError> {
    let user = state
        .db
        .users()
        .create(&body.username, &body.password, &body.display_name)
        .await
        .map_err(|e| {
            if e.is_unique_violation() {
                ApiError::new(StatusCode::CONFLICT, "Username already exists")
            } else {
                ApiError::from(e)
            }
        })?;
    let is_admin = state.db.users().is_admin(user.id).await?;
    Ok((StatusCode::CREATED, Json(UserResponse::from_user(user, is_admin))))
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    AuthUser(_): AuthUser,
) -> Result<Json<Vec<UserResponse>>, ApiError> {
    let users = state.db.users().list_all().await?;
    let mut out = Vec::with_capacity(users.len());
    for u in users {
        let admin = state.db.users().is_admin(u.id).await?;
        out.push(UserResponse::from_user(u, admin));
    }
    Ok(Json(out))
}

async fn get_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    AuthUser(_): AuthUser,
) -> Result<Json<UserResponse>, ApiError> {
    let user = state
        .db
        .users()
        .get_by_id(user_id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "User not found"))?;
    let is_admin = state.db.users().is_admin(user.id).await?;
    Ok(Json(UserResponse::from_user(user, is_admin)))
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    AuthUser(current): AuthUser,
    Json(body): Json<UserPatch>,
) -> Result<Json<UserResponse>, ApiError> {
    let caller_is_admin = state.db.users().is_admin(current.id).await?;
    if current.id != user_id && !caller_is_admin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Admin privileges required"));
    }
    let updated = state
        .db
        .users()
        .update(
            user_id,
            UserUpdate {
                username: body.username,
                password: body.password,
                display_name: body.display_name,
                is_active: body.is_active,
            },
        )
        .await
        .map_err(|e| {
            if e.is_unique_violation() {
                ApiError::new(StatusCode::CONFLICT, "Username already exists")
            } else {
                ApiError::from(e)
            }
        })?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "User not found"))?;
    let is_admin = state.db.users().is_admin(updated.id).await?;
    Ok(Json(UserResponse::from_user(updated, is_admin)))
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    AuthUser(current): AuthUser,
) -> Result<StatusCode, ApiError> {
    let caller_is_admin = state.db.users().is_admin(current.id).await?;
    if current.id != user_id && !caller_is_admin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Admin privileges required"));
    }
    if !state.db.users().delete(user_id).await? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "User not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_user_groups(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    AuthUser(_): AuthUser,
) -> Result<Json<Vec<GroupResponse>>, ApiError> {
    let groups = state.db.groups().get_user_groups(user_id).await?;
    Ok(Json(groups.into_iter().map(Into::into).collect()))
}

async fn create_group(
    State(state): State<Arc<AppState>>,
    AdminUser(_): AdminUser,
    Json(body): Json<GroupCreate>,
) -> Result<(StatusCode, Json<GroupResponse>), ApiError> {
    let group = state
        .db
        .groups()
        .create(&body.name, &body.description, body.is_admin)
        .await
        .map_err(|e| {
            if e.is_unique_violation() {
                ApiError::new(StatusCode::CONFLICT, "Group name already exists")
            } else {
                ApiError::from(e)
            }
        })?;
    Ok((StatusCode::CREATED, Json(group.into())))
}

async fn list_groups(
    State(state): State<Arc<AppState>>,
    AuthUser(_): AuthUser,
) -> Result<Json<Vec<GroupResponse>>, ApiError> {
    let groups = state.db.groups().list_all().await?;
    Ok(Json(groups.into_iter().map(Into::into).collect()))
}

async fn get_group(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    AuthUser(_): AuthUser,
) -> Result<Json<GroupResponse>, ApiError> {
    let group = state
        .db
        .groups()
        .get_by_id(group_id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Group not found"))?;
    Ok(Json(group.into()))
}

async fn update_group(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    AdminUser(_): AdminUser,
    Json(body): Json<GroupPatch>,
) -> Result<Json<GroupResponse>, ApiError> {
    let updated = state
        .db
        .groups()
        .update(
            group_id,
            GroupUpdate {
                name: body.name,
                description: body.description,
                is_admin: body.is_admin,
            },
        )
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Group not found"))?;
    Ok(Json(updated.into()))
}

async fn delete_group(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    AdminUser(_): AdminUser,
) -> Result<StatusCode, ApiError> {
    if !state.db.groups().delete(group_id).await? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Group not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn add_member(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    AdminUser(_): AdminUser,
    Json(body): Json<GroupMember>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if body.group_id != group_id {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "group_id mismatch"));
    }
    if !state.db.groups().add_user(group_id, body.user_id).await? {
        return Err(ApiError::new(StatusCode::CONFLICT, "Already a member"));
    }
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"detail": "Member added"})),
    ))
}

async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path((group_id, user_id)): Path<(i64, i64)>,
    AdminUser(_): AdminUser,
) -> Result<StatusCode, ApiError> {
    if !state.db.groups().remove_user(group_id, user_id).await? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Member not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    AuthUser(_): AuthUser,
) -> Result<Json<Vec<UserResponse>>, ApiError> {
    let members = state.db.groups().get_members(group_id).await?;
    let mut out = Vec::with_capacity(members.len());
    for m in members {
        let admin = state.db.users().is_admin(m.id).await?;
        out.push(UserResponse::from_user(m, admin));
    }
    Ok(Json(out))
}

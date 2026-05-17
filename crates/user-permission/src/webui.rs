//! HTMX + Tailwind WebUI ported from the legacy `webui.py`.
//!
//! Layout: 12 askama templates live under `crates/user-permission/templates/`,
//! 24 handlers below cover the same routes the FastAPI version provided.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::header::{CONTENT_TYPE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use serde::Deserialize;
use user_permission_core::{Group, GroupUpdate, User, UserUpdate};

use crate::state::AppState;

const COOKIE_NAME: &str = "up_token";
const HX_REQUEST: HeaderName = HeaderName::from_static("hx-request");
const HX_REDIRECT: HeaderName = HeaderName::from_static("hx-redirect");

// ---------------------------------------------------------------------------
// View structs
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
    pub is_admin: bool,
}

impl UserView {
    fn from_user(u: User, is_admin: bool) -> Self {
        Self {
            id: u.id,
            username: u.username,
            display_name: u.display_name,
            is_active: u.is_active,
            created_at: u.created_at,
            updated_at: u.updated_at,
            is_admin,
        }
    }
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    prefix: &'a str,
    user: Option<&'a UserView>,
    is_admin: bool,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate<'a> {
    prefix: &'a str,
    user: Option<&'a UserView>,
    is_admin: bool,
    error: Option<&'a str>,
    values_username: &'a str,
    values_display_name: &'a str,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    prefix: &'a str,
    user: Option<&'a UserView>,
    is_admin: bool,
    user_count: usize,
    group_count: usize,
    my_groups: &'a [Group],
}

#[derive(Template)]
#[template(path = "users.html")]
struct UsersTemplate<'a> {
    prefix: &'a str,
    user: Option<&'a UserView>,
    is_admin: bool,
    users: &'a [UserView],
    current_user_id: i64,
}

#[derive(Template)]
#[template(path = "user_row.html")]
struct UserRowTemplate<'a> {
    prefix: &'a str,
    u: &'a UserView,
    current_user_id: i64,
    is_admin: bool,
}

#[derive(Template)]
#[template(path = "me.html")]
struct MeTemplate<'a> {
    prefix: &'a str,
    user: Option<&'a UserView>,
    is_admin: bool,
    my_groups: &'a [Group],
    profile_success: bool,
    profile_error: Option<&'a str>,
    password_success: bool,
    password_error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "user_edit.html")]
struct UserEditTemplate<'a> {
    prefix: &'a str,
    user: Option<&'a UserView>,
    is_admin: bool,
    target: &'a UserView,
    target_is_admin: bool,
    target_groups: &'a [Group],
    profile_success: bool,
    profile_error: Option<&'a str>,
    password_success: bool,
    password_error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "groups.html")]
struct GroupsTemplate<'a> {
    prefix: &'a str,
    user: Option<&'a UserView>,
    is_admin: bool,
    groups: &'a [Group],
}

#[derive(Template)]
#[template(path = "group_row.html")]
struct GroupRowTemplate<'a> {
    prefix: &'a str,
    g: &'a Group,
    is_admin: bool,
}

#[derive(Template)]
#[template(path = "group_detail.html")]
struct GroupDetailTemplate<'a> {
    prefix: &'a str,
    user: Option<&'a UserView>,
    is_admin: bool,
    group: &'a Group,
    members: &'a [User],
    non_members: &'a [User],
    update_success: bool,
    update_error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "member_row.html")]
struct MemberRowTemplate<'a> {
    prefix: &'a str,
    u: &'a User,
    group: &'a Group,
    is_admin: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn render<T: Template>(tpl: T) -> Response {
    match tpl.render() {
        Ok(html) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "template render failed",
            )
                .into_response()
        }
    }
}

fn render_with_status<T: Template>(tpl: T, status: StatusCode) -> Response {
    match tpl.render() {
        Ok(html) => (
            status,
            [(CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "template render failed",
            )
                .into_response()
        }
    }
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    let needle = format!("{COOKIE_NAME}=");
    for piece in raw.split(';') {
        let p = piece.trim();
        if let Some(v) = p.strip_prefix(&needle) {
            return Some(v.to_string());
        }
    }
    None
}

fn set_cookie_value(token: &str, max_age_secs: i64) -> String {
    format!(
        "{COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}"
    )
}

fn delete_cookie_value() -> String {
    format!("{COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

fn is_htmx(headers: &HeaderMap) -> bool {
    headers
        .get(&HX_REQUEST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn redirect_to(target: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(LOCATION, HeaderValue::from_str(target).unwrap_or(HeaderValue::from_static("/")))],
    )
        .into_response()
}

fn redirect_to_login(prefix: &str, htmx: bool) -> Response {
    let target = format!("{prefix}/login");
    if htmx {
        (
            StatusCode::UNAUTHORIZED,
            [(HX_REDIRECT, HeaderValue::from_str(&target).unwrap_or(HeaderValue::from_static("/login")))],
        )
            .into_response()
    } else {
        redirect_to(&target)
    }
}

async fn current_user(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Option<UserView> {
    let token = cookie_token(headers)?;
    let claims = state.db.token_manager().ok()?.verify_token(&token).ok()?;
    let user_id: i64 = claims.get("sub")?.as_str()?.parse().ok()?;
    let user = state.db.users().get_by_id(user_id).await.ok()??;
    if !user.is_active {
        return None;
    }
    let is_admin = state.db.users().is_admin(user.id).await.ok()?;
    Some(UserView::from_user(user, is_admin))
}

fn prefix(state: &AppState) -> &str {
    state.config.webui_prefix.trim_end_matches('/')
}

fn webui_token_secs(state: &AppState) -> i64 {
    state.config.webui_token_expires.as_secs() as i64
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Register every WebUI route under the given prefix. Uses `Router::merge`
/// (not `nest`) because axum 0.7's nest does not dispatch trailing-slash
/// requests like `/ui/` to the inner router's `/` route.
pub fn router(prefix: &str) -> Router<Arc<AppState>> {
    let p = prefix.trim_end_matches('/');
    let join = |path: &str| -> String {
        if p.is_empty() {
            format!("/{path}")
        } else {
            format!("{p}/{path}")
        }
    };
    let mut r: Router<Arc<AppState>> = Router::new();
    if p.is_empty() {
        r = r.route("/", get(index));
    } else {
        // `/ui` and `/ui/` both serve the dashboard.
        r = r.route(p, get(index)).route(&format!("{p}/"), get(index));
    }
    r.route(&join("login"), get(login_page).post(login_submit))
        .route(&join("logout"), get(logout).post(logout))
        .route(&join("register"), get(register_page).post(register_submit))
        .route(&join("me"), get(me_page).post(me_update))
        .route(&join("me/password"), post(me_password))
        .route(&join("users"), get(users_page).post(users_create))
        .route(
            &join("users/:user_id"),
            get(users_edit_page).post(users_edit_submit).delete(users_delete),
        )
        .route(&join("users/:user_id/active"), post(users_toggle_active))
        .route(&join("users/:user_id/admin"), post(users_toggle_admin))
        .route(&join("users/:user_id/password"), post(users_reset_password))
        .route(&join("groups"), get(groups_page).post(groups_create))
        .route(
            &join("groups/:group_id"),
            get(group_detail).post(group_update).delete(group_delete),
        )
        .route(&join("groups/:group_id/members"), post(group_add_member))
        .route(
            &join("groups/:group_id/members/:user_id"),
            delete(group_remove_member),
        )
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

async fn login_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    if current_user(&state, &headers).await.is_some() {
        return redirect_to(&format!("{prefix}/"));
    }
    render(LoginTemplate {
        prefix: &prefix,
        user: None,
        is_admin: false,
        error: None,
    })
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let expires = state.config.webui_token_expires;
    match state
        .db
        .users()
        .authenticate(&form.username, &form.password, expires)
        .await
    {
        Ok(Some(token)) => {
            let max_age = webui_token_secs(&state);
            let cookie = set_cookie_value(&token, max_age);
            let target = format!("{prefix}/");
            (
                StatusCode::SEE_OTHER,
                [
                    (LOCATION, HeaderValue::from_str(&target).unwrap()),
                    (SET_COOKIE, HeaderValue::from_str(&cookie).unwrap()),
                ],
            )
                .into_response()
        }
        _ => render_with_status(
            LoginTemplate {
                prefix: &prefix,
                user: None,
                is_admin: false,
                error: Some("ユーザー名またはパスワードが間違っています"),
            },
            StatusCode::OK,
        ),
    }
}

async fn logout(State(state): State<Arc<AppState>>) -> Response {
    let prefix = prefix(&state).to_string();
    let target = format!("{prefix}/login");
    let cookie = delete_cookie_value();
    (
        StatusCode::SEE_OTHER,
        [
            (LOCATION, HeaderValue::from_str(&target).unwrap()),
            (SET_COOKIE, HeaderValue::from_str(&cookie).unwrap()),
        ],
    )
        .into_response()
}

async fn register_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    if current_user(&state, &headers).await.is_some() {
        return redirect_to(&format!("{prefix}/"));
    }
    render(RegisterTemplate {
        prefix: &prefix,
        user: None,
        is_admin: false,
        error: None,
        values_username: "",
        values_display_name: "",
    })
}

#[derive(Deserialize)]
struct RegisterForm {
    username: String,
    password: String,
    #[serde(default)]
    display_name: String,
}

async fn register_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<RegisterForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let expires = state.config.webui_token_expires;
    if let Err(err) = state
        .db
        .users()
        .create(&form.username, &form.password, &form.display_name)
        .await
    {
        let msg = if err.is_unique_violation() {
            "そのユーザー名は既に使われています"
        } else {
            "登録に失敗しました"
        };
        return render(RegisterTemplate {
            prefix: &prefix,
            user: None,
            is_admin: false,
            error: Some(msg),
            values_username: &form.username,
            values_display_name: &form.display_name,
        });
    }
    let target = format!("{prefix}/");
    match state
        .db
        .users()
        .authenticate(&form.username, &form.password, expires)
        .await
    {
        Ok(Some(token)) => {
            let cookie = set_cookie_value(&token, webui_token_secs(&state));
            (
                StatusCode::SEE_OTHER,
                [
                    (LOCATION, HeaderValue::from_str(&target).unwrap()),
                    (SET_COOKIE, HeaderValue::from_str(&cookie).unwrap()),
                ],
            )
                .into_response()
        }
        _ => redirect_to(&target),
    }
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(user) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    let users = match state.db.users().list_all().await {
        Ok(v) => v,
        Err(_) => return server_error_response(),
    };
    let groups = match state.db.groups().list_all().await {
        Ok(v) => v,
        Err(_) => return server_error_response(),
    };
    let my_groups = match state.db.groups().get_user_groups(user.id).await {
        Ok(v) => v,
        Err(_) => return server_error_response(),
    };
    render(IndexTemplate {
        prefix: &prefix,
        user: Some(&user),
        is_admin: user.is_admin,
        user_count: users.len(),
        group_count: groups.len(),
        my_groups: &my_groups,
    })
}

fn server_error_response() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

// ---------------------------------------------------------------------------
// Profile (/me)
// ---------------------------------------------------------------------------

async fn me_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(user) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    let my_groups = match state.db.groups().get_user_groups(user.id).await {
        Ok(v) => v,
        Err(_) => return server_error_response(),
    };
    render(MeTemplate {
        prefix: &prefix,
        user: Some(&user),
        is_admin: user.is_admin,
        my_groups: &my_groups,
        profile_success: false,
        profile_error: None,
        password_success: false,
        password_error: None,
    })
}

#[derive(Deserialize)]
struct MeUpdateForm {
    username: String,
    #[serde(default)]
    display_name: String,
}

async fn me_update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<MeUpdateForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(user) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    let update = state
        .db
        .users()
        .update(
            user.id,
            UserUpdate {
                username: Some(form.username),
                display_name: Some(form.display_name),
                ..Default::default()
            },
        )
        .await;
    let my_groups = state
        .db
        .groups()
        .get_user_groups(user.id)
        .await
        .unwrap_or_default();
    match update {
        Ok(Some(updated)) => {
            let updated_view = UserView::from_user(updated, user.is_admin);
            render(MeTemplate {
                prefix: &prefix,
                user: Some(&updated_view),
                is_admin: user.is_admin,
                my_groups: &my_groups,
                profile_success: true,
                profile_error: None,
                password_success: false,
                password_error: None,
            })
        }
        Err(err) if err.is_unique_violation() => render(MeTemplate {
            prefix: &prefix,
            user: Some(&user),
            is_admin: user.is_admin,
            my_groups: &my_groups,
            profile_success: false,
            profile_error: Some("そのユーザー名は既に使われています"),
            password_success: false,
            password_error: None,
        }),
        _ => render(MeTemplate {
            prefix: &prefix,
            user: Some(&user),
            is_admin: user.is_admin,
            my_groups: &my_groups,
            profile_success: false,
            profile_error: Some("更新に失敗しました"),
            password_success: false,
            password_error: None,
        }),
    }
}

#[derive(Deserialize)]
struct MePasswordForm {
    current_password: String,
    new_password: String,
}

async fn me_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<MePasswordForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(user) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    let my_groups = state
        .db
        .groups()
        .get_user_groups(user.id)
        .await
        .unwrap_or_default();
    let one_hour = std::time::Duration::from_secs(3600);
    match state
        .db
        .users()
        .authenticate(&user.username, &form.current_password, one_hour)
        .await
    {
        Ok(Some(_)) => {
            let _ = state
                .db
                .users()
                .update(
                    user.id,
                    UserUpdate {
                        password: Some(form.new_password),
                        ..Default::default()
                    },
                )
                .await;
            render(MeTemplate {
                prefix: &prefix,
                user: Some(&user),
                is_admin: user.is_admin,
                my_groups: &my_groups,
                profile_success: false,
                profile_error: None,
                password_success: true,
                password_error: None,
            })
        }
        _ => render(MeTemplate {
            prefix: &prefix,
            user: Some(&user),
            is_admin: user.is_admin,
            my_groups: &my_groups,
            profile_success: false,
            profile_error: None,
            password_success: false,
            password_error: Some("現在のパスワードが一致しません"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

async fn build_user_view(state: &Arc<AppState>, u: User) -> UserView {
    let is_admin = state
        .db
        .users()
        .is_admin(u.id)
        .await
        .unwrap_or(false);
    UserView::from_user(u, is_admin)
}

async fn users_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(user) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    let raw = match state.db.users().list_all().await {
        Ok(v) => v,
        Err(_) => return server_error_response(),
    };
    let mut views = Vec::with_capacity(raw.len());
    for u in raw {
        views.push(build_user_view(&state, u).await);
    }
    render(UsersTemplate {
        prefix: &prefix,
        user: Some(&user),
        is_admin: user.is_admin,
        users: &views,
        current_user_id: user.id,
    })
}

#[derive(Deserialize)]
struct UserCreateForm {
    username: String,
    password: String,
    #[serde(default)]
    display_name: String,
}

async fn users_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<UserCreateForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    match state
        .db
        .users()
        .create(&form.username, &form.password, &form.display_name)
        .await
    {
        Ok(new_user) => {
            let view = build_user_view(&state, new_user).await;
            render_with_status(
                UserRowTemplate {
                    prefix: &prefix,
                    u: &view,
                    current_user_id: current.id,
                    is_admin: current.is_admin,
                },
                StatusCode::CREATED,
            )
        }
        Err(err) if err.is_unique_violation() => (
            StatusCode::CONFLICT,
            "そのユーザー名は既に使われています",
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "作成に失敗しました").into_response(),
    }
}

async fn users_delete(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if current.id != user_id && !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    match state.db.users().delete(user_id).await {
        Ok(true) => {
            if current.id == user_id {
                let target = format!("{prefix}/login");
                let cookie = delete_cookie_value();
                (
                    StatusCode::OK,
                    [
                        (HX_REDIRECT, HeaderValue::from_str(&target).unwrap()),
                        (SET_COOKIE, HeaderValue::from_str(&cookie).unwrap()),
                        (CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8")),
                    ],
                    "",
                )
                    .into_response()
            } else {
                (StatusCode::OK, "").into_response()
            }
        }
        Ok(false) => (StatusCode::NOT_FOUND, "ユーザーが見つかりません").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "削除に失敗しました").into_response(),
    }
}

async fn users_toggle_active(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if current.id != user_id && !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    let target = match state.db.users().get_by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "ユーザーが見つかりません").into_response(),
        Err(_) => return server_error_response(),
    };
    let updated = match state
        .db
        .users()
        .update(
            user_id,
            UserUpdate {
                is_active: Some(!target.is_active),
                ..Default::default()
            },
        )
        .await
    {
        Ok(Some(u)) => u,
        _ => return (StatusCode::NOT_FOUND, "ユーザーが見つかりません").into_response(),
    };
    let view = build_user_view(&state, updated).await;
    render(UserRowTemplate {
        prefix: &prefix,
        u: &view,
        current_user_id: current.id,
        is_admin: current.is_admin,
    })
}

async fn users_toggle_admin(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    if current.id == user_id {
        return (
            StatusCode::BAD_REQUEST,
            "自分自身の管理者状態は変更できません",
        )
            .into_response();
    }
    let target = match state.db.users().get_by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "ユーザーが見つかりません").into_response(),
        Err(_) => return server_error_response(),
    };
    let currently_admin = state
        .db
        .users()
        .is_admin(user_id)
        .await
        .unwrap_or(false);
    let _ = state.db.users().set_admin(user_id, !currently_admin).await;
    let view = build_user_view(&state, target).await;
    render(UserRowTemplate {
        prefix: &prefix,
        u: &view,
        current_user_id: current.id,
        is_admin: current.is_admin,
    })
}

async fn users_edit_page(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if current.id == user_id {
        return redirect_to(&format!("{prefix}/me"));
    }
    if !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    let target = match state.db.users().get_by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "ユーザーが見つかりません").into_response(),
        Err(_) => return server_error_response(),
    };
    let target_view = build_user_view(&state, target).await;
    let target_groups = state
        .db
        .groups()
        .get_user_groups(user_id)
        .await
        .unwrap_or_default();
    render(UserEditTemplate {
        prefix: &prefix,
        user: Some(&current),
        is_admin: current.is_admin,
        target: &target_view,
        target_is_admin: target_view.is_admin,
        target_groups: &target_groups,
        profile_success: false,
        profile_error: None,
        password_success: false,
        password_error: None,
    })
}

#[derive(Deserialize)]
struct UserEditForm {
    username: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    is_active: Option<String>,
}

async fn users_edit_submit(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<UserEditForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if current.id == user_id {
        return redirect_to(&format!("{prefix}/me"));
    }
    if !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    let target = match state.db.users().get_by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "ユーザーが見つかりません").into_response(),
        Err(_) => return server_error_response(),
    };
    let target_is_admin = state.db.users().is_admin(user_id).await.unwrap_or(false);
    let target_groups = state
        .db
        .groups()
        .get_user_groups(user_id)
        .await
        .unwrap_or_default();
    let is_active = form.is_active.is_some();
    let update_result = state
        .db
        .users()
        .update(
            user_id,
            UserUpdate {
                username: Some(form.username),
                display_name: Some(form.display_name),
                is_active: Some(is_active),
                ..Default::default()
            },
        )
        .await;
    match update_result {
        Ok(Some(updated)) => {
            let view = UserView::from_user(updated, target_is_admin);
            render(UserEditTemplate {
                prefix: &prefix,
                user: Some(&current),
                is_admin: current.is_admin,
                target: &view,
                target_is_admin,
                target_groups: &target_groups,
                profile_success: true,
                profile_error: None,
                password_success: false,
                password_error: None,
            })
        }
        Err(err) if err.is_unique_violation() => {
            let view = UserView::from_user(target, target_is_admin);
            render(UserEditTemplate {
                prefix: &prefix,
                user: Some(&current),
                is_admin: current.is_admin,
                target: &view,
                target_is_admin,
                target_groups: &target_groups,
                profile_success: false,
                profile_error: Some("そのユーザー名は既に使われています"),
                password_success: false,
                password_error: None,
            })
        }
        _ => {
            let view = UserView::from_user(target, target_is_admin);
            render(UserEditTemplate {
                prefix: &prefix,
                user: Some(&current),
                is_admin: current.is_admin,
                target: &view,
                target_is_admin,
                target_groups: &target_groups,
                profile_success: false,
                profile_error: Some("更新に失敗しました"),
                password_success: false,
                password_error: None,
            })
        }
    }
}

#[derive(Deserialize)]
struct UserResetPasswordForm {
    new_password: String,
}

async fn users_reset_password(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<UserResetPasswordForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if current.id == user_id {
        return redirect_to(&format!("{prefix}/me"));
    }
    if !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    let target = match state.db.users().get_by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "ユーザーが見つかりません").into_response(),
        Err(_) => return server_error_response(),
    };
    let _ = state
        .db
        .users()
        .update(
            user_id,
            UserUpdate {
                password: Some(form.new_password),
                ..Default::default()
            },
        )
        .await;
    let target_is_admin = state.db.users().is_admin(user_id).await.unwrap_or(false);
    let target_groups = state
        .db
        .groups()
        .get_user_groups(user_id)
        .await
        .unwrap_or_default();
    let view = UserView::from_user(target, target_is_admin);
    render(UserEditTemplate {
        prefix: &prefix,
        user: Some(&current),
        is_admin: current.is_admin,
        target: &view,
        target_is_admin,
        target_groups: &target_groups,
        profile_success: false,
        profile_error: None,
        password_success: true,
        password_error: None,
    })
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

async fn groups_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(user) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    let groups = match state.db.groups().list_all().await {
        Ok(v) => v,
        Err(_) => return server_error_response(),
    };
    render(GroupsTemplate {
        prefix: &prefix,
        user: Some(&user),
        is_admin: user.is_admin,
        groups: &groups,
    })
}

#[derive(Deserialize)]
struct GroupCreateForm {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    is_admin: Option<String>,
}

async fn groups_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<GroupCreateForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    match state
        .db
        .groups()
        .create(&form.name, &form.description, form.is_admin.is_some())
        .await
    {
        Ok(group) => render_with_status(
            GroupRowTemplate {
                prefix: &prefix,
                g: &group,
                is_admin: current.is_admin,
            },
            StatusCode::CREATED,
        ),
        Err(err) if err.is_unique_violation() => (
            StatusCode::CONFLICT,
            "そのグループ名は既に使われています",
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "作成に失敗しました").into_response(),
    }
}

async fn group_detail(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(user) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    let group = match state.db.groups().get_by_id(group_id).await {
        Ok(Some(g)) => g,
        Ok(None) => return (StatusCode::NOT_FOUND, "グループが見つかりません").into_response(),
        Err(_) => return server_error_response(),
    };
    let members = state
        .db
        .groups()
        .get_members(group_id)
        .await
        .unwrap_or_default();
    let non_members = if user.is_admin {
        let member_ids: std::collections::HashSet<i64> = members.iter().map(|u| u.id).collect();
        state
            .db
            .users()
            .list_all()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|u| !member_ids.contains(&u.id))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    render(GroupDetailTemplate {
        prefix: &prefix,
        user: Some(&user),
        is_admin: user.is_admin,
        group: &group,
        members: &members,
        non_members: &non_members,
        update_success: false,
        update_error: None,
    })
}

#[derive(Deserialize)]
struct GroupUpdateForm {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    is_admin: Option<String>,
}

async fn group_update(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<GroupUpdateForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(user) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if !user.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    let existing = match state.db.groups().get_by_id(group_id).await {
        Ok(Some(g)) => g,
        Ok(None) => return (StatusCode::NOT_FOUND, "グループが見つかりません").into_response(),
        Err(_) => return server_error_response(),
    };
    let update = state
        .db
        .groups()
        .update(
            group_id,
            GroupUpdate {
                name: Some(form.name),
                description: Some(form.description),
                is_admin: Some(form.is_admin.is_some()),
            },
        )
        .await;
    let (group_to_show, error_msg) = match update {
        Ok(Some(g)) => (g, None),
        Err(err) if err.is_unique_violation() => (
            existing,
            Some("そのグループ名は既に使われています"),
        ),
        _ => (existing, Some("更新に失敗しました")),
    };
    let members = state
        .db
        .groups()
        .get_members(group_id)
        .await
        .unwrap_or_default();
    let member_ids: std::collections::HashSet<i64> = members.iter().map(|u| u.id).collect();
    let non_members = state
        .db
        .users()
        .list_all()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|u| !member_ids.contains(&u.id))
        .collect::<Vec<_>>();
    render(GroupDetailTemplate {
        prefix: &prefix,
        user: Some(&user),
        is_admin: user.is_admin,
        group: &group_to_show,
        members: &members,
        non_members: &non_members,
        update_success: error_msg.is_none(),
        update_error: error_msg,
    })
}

async fn group_delete(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    match state.db.groups().delete(group_id).await {
        Ok(true) => (StatusCode::OK, "").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "グループが見つかりません").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "削除に失敗しました").into_response(),
    }
}

#[derive(Deserialize)]
struct AddMemberForm {
    user_id: i64,
}

async fn group_add_member(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<i64>,
    headers: HeaderMap,
    Form(form): Form<AddMemberForm>,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    let group = match state.db.groups().get_by_id(group_id).await {
        Ok(Some(g)) => g,
        _ => return (StatusCode::NOT_FOUND, "対象が見つかりません").into_response(),
    };
    let target = match state.db.users().get_by_id(form.user_id).await {
        Ok(Some(u)) => u,
        _ => return (StatusCode::NOT_FOUND, "対象が見つかりません").into_response(),
    };
    match state.db.groups().add_user(group_id, form.user_id).await {
        Ok(true) => render_with_status(
            MemberRowTemplate {
                prefix: &prefix,
                u: &target,
                group: &group,
                is_admin: current.is_admin,
            },
            StatusCode::CREATED,
        ),
        Ok(false) => (StatusCode::CONFLICT, "既にメンバーです").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "追加に失敗しました").into_response(),
    }
}

async fn group_remove_member(
    State(state): State<Arc<AppState>>,
    Path((group_id, user_id)): Path<(i64, i64)>,
    headers: HeaderMap,
) -> Response {
    let prefix = prefix(&state).to_string();
    let Some(current) = current_user(&state, &headers).await else {
        return redirect_to_login(&prefix, is_htmx(&headers));
    };
    if !current.is_admin {
        return (StatusCode::FORBIDDEN, "管理者権限が必要です").into_response();
    }
    match state.db.groups().remove_user(group_id, user_id).await {
        Ok(true) => (StatusCode::OK, "").into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "メンバーが見つかりません").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "削除に失敗しました").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Placeholder fallback (kept so unknown WebUI paths fall back to the index).
// ---------------------------------------------------------------------------

pub async fn placeholder() -> Response {
    redirect_to("/ui/")
}

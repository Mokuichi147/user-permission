use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use user_permission_core::Error as CoreError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub detail: String,
    pub bearer_challenge: bool,
}

impl ApiError {
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
            bearer_challenge: false,
        }
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        let mut err = Self::new(StatusCode::UNAUTHORIZED, detail);
        err.bearer_challenge = true;
        err
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, detail)
    }

    pub fn with_bearer(mut self) -> Self {
        self.bearer_challenge = true;
        self
    }
}

impl From<CoreError> for ApiError {
    fn from(value: CoreError) -> Self {
        match value {
            CoreError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "Not found"),
            CoreError::Conflict(msg) => ApiError::new(StatusCode::CONFLICT, msg),
            CoreError::InvalidCredentials => {
                let mut err =
                    ApiError::new(StatusCode::UNAUTHORIZED, "Invalid username or password");
                err.bearer_challenge = true;
                err
            }
            CoreError::MissingTokenManager => {
                ApiError::internal("token manager not configured")
            }
            err if err.is_unique_violation() => {
                ApiError::new(StatusCode::CONFLICT, err.to_string())
            }
            other => ApiError::internal(other.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({ "detail": self.detail }));
        let mut headers = HeaderMap::new();
        if self.bearer_challenge {
            headers.insert(
                axum::http::header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer"),
            );
        }
        (self.status, headers, body).into_response()
    }
}

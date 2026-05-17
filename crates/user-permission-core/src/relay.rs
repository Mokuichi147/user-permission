use std::sync::RwLock;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{Error, Result};

pub(crate) struct RelayBackend {
    client: reqwest::Client,
    base_url: String,
    token: RwLock<Option<String>>,
}

impl RelayBackend {
    pub(crate) fn new(url: &str) -> Result<Self> {
        // Normalise base URL (no trailing slash) and validate.
        let parsed = url::Url::parse(url)?;
        let base_url = parsed.as_str().trim_end_matches('/').to_string();
        Ok(Self {
            client: reqwest::Client::builder().build()?,
            base_url,
            token: RwLock::new(None),
        })
    }

    pub(crate) fn set_token(&self, token: Option<String>) {
        let mut guard = self.token.write().expect("relay token lock poisoned");
        *guard = token;
    }

    fn current_token(&self) -> Option<String> {
        self.token.read().ok().and_then(|g| g.clone())
    }

    pub(crate) async fn login(&self, username: &str, password: &str) -> Result<String> {
        let url = format!("{}/token", self.base_url);
        let resp = self
            .client
            .post(&url)
            .form(&[("username", username), ("password", password)])
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Relay { status, body });
        }
        let body: Value = resp.json().await?;
        let token = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Relay {
                status: 200,
                body: "no access_token in response".into(),
            })?
            .to_string();
        self.set_token(Some(token.clone()));
        Ok(token)
    }

    /// Execute a JSON request and decode the response as `T`. `auth = true` attaches
    /// `Authorization: Bearer <token>` (the token must have been stored via `login`).
    pub(crate) async fn request_json<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: bool,
    ) -> Result<T> {
        let resp = self.send(method, path, body, auth).await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Relay { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Like `request_json` but returns `Ok(None)` on 404.
    pub(crate) async fn request_json_opt<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: bool,
    ) -> Result<Option<T>> {
        let resp = self.send(method, path, body, auth).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Relay { status, body });
        }
        Ok(Some(resp.json().await?))
    }

    /// Returns `true` if status is 204 (No Content).
    pub(crate) async fn request_no_content(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: bool,
    ) -> Result<bool> {
        let resp = self.send(method, path, body, auth).await?;
        Ok(resp.status() == reqwest::StatusCode::NO_CONTENT)
    }

    pub(crate) async fn request_no_content_strict(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: bool,
        expected: u16,
    ) -> Result<bool> {
        let resp = self.send(method, path, body, auth).await?;
        Ok(resp.status().as_u16() == expected)
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: bool,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::InvalidArgument(e.to_string()))?;
        let mut req = self.client.request(m, &url);
        if auth {
            if let Some(token) = self.current_token() {
                req = req.bearer_auth(token);
            }
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        Ok(req.send().await?)
    }
}

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

    /// Resolve which bearer token to use for a request: prefer the per-call
    /// `override_token` if provided, otherwise fall back to the internally
    /// stored token (set via `login` or `set_token`). Returns `None` if neither
    /// is available, in which case no `Authorization` header should be sent.
    pub(crate) fn resolve_auth(&self, override_token: Option<&str>) -> Option<String> {
        override_token
            .map(str::to_owned)
            .or_else(|| self.current_token())
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

    /// Execute a JSON request and decode the response as `T`. If `auth` is
    /// `Some(token)`, attaches `Authorization: Bearer <token>`; if `None`, no
    /// `Authorization` header is sent. Callers typically obtain the value via
    /// [`Self::resolve_auth`] so per-call tokens take precedence over the
    /// internally stored token.
    pub(crate) async fn request_json<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: Option<&str>,
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
        auth: Option<&str>,
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
        auth: Option<&str>,
    ) -> Result<bool> {
        let resp = self.send(method, path, body, auth).await?;
        Ok(resp.status() == reqwest::StatusCode::NO_CONTENT)
    }

    pub(crate) async fn request_no_content_strict(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: Option<&str>,
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
        auth: Option<&str>,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::InvalidArgument(e.to_string()))?;
        let mut req = self.client.request(m, &url);
        if let Some(token) = auth {
            req = req.bearer_auth(token);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        Ok(req.send().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_auth_prefers_override() {
        let backend = RelayBackend::new("http://example.com").unwrap();
        backend.set_token(Some("stored".into()));
        assert_eq!(
            backend.resolve_auth(Some("per-call")),
            Some("per-call".to_string())
        );
    }

    #[test]
    fn resolve_auth_falls_back_to_stored() {
        let backend = RelayBackend::new("http://example.com").unwrap();
        backend.set_token(Some("stored".into()));
        assert_eq!(backend.resolve_auth(None), Some("stored".to_string()));
    }

    #[test]
    fn resolve_auth_returns_none_without_token() {
        let backend = RelayBackend::new("http://example.com").unwrap();
        assert_eq!(backend.resolve_auth(None), None);
    }
}

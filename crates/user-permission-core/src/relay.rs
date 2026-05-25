use std::sync::RwLock;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{Error, Result};

pub(crate) struct RelayBackend {
    client: reqwest::Client,
    base_url: String,
    token: RwLock<Option<String>>,
    /// Stored client-credentials, set by `login_client_credentials`, used to
    /// transparently re-issue the access token when a request gets a 401.
    client_creds: RwLock<Option<(String, String)>>,
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
            client_creds: RwLock::new(None),
        })
    }

    pub(crate) fn set_token(&self, token: Option<String>) {
        let mut guard = self.token.write().expect("relay token lock poisoned");
        *guard = token;
    }

    fn current_token(&self) -> Option<String> {
        self.token.read().ok().and_then(|g| g.clone())
    }

    fn current_creds(&self) -> Option<(String, String)> {
        self.client_creds.read().ok().and_then(|g| g.clone())
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

    /// Authenticate as a service via the OAuth2 client-credentials grant. The
    /// issued access token is stored, and the credentials are retained so the
    /// token can be refreshed transparently when a later request returns 401.
    pub(crate) async fn login_client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<String> {
        let token = self.fetch_client_token(client_id, client_secret).await?;
        self.set_token(Some(token.clone()));
        *self
            .client_creds
            .write()
            .expect("relay creds lock poisoned") = Some((client_id.into(), client_secret.into()));
        Ok(token)
    }

    async fn fetch_client_token(&self, client_id: &str, client_secret: &str) -> Result<String> {
        let url = format!("{}/token", self.base_url);
        let resp = self
            .client
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Relay { status, body });
        }
        let body: Value = resp.json().await?;
        body.get("access_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::Relay {
                status: 200,
                body: "no access_token in response".into(),
            })
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
        let resp = self.send_once(method, path, body.clone(), auth).await?;
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }
        // Only refresh when the request used the internally stored token (not a
        // per-call override) and we hold client credentials.
        let used_stored = match auth {
            Some(a) => Some(a.to_string()) == self.current_token(),
            None => true,
        };
        if !used_stored {
            return Ok(resp);
        }
        let Some((client_id, secret)) = self.current_creds() else {
            return Ok(resp);
        };
        let token = self.fetch_client_token(&client_id, &secret).await?;
        self.set_token(Some(token.clone()));
        self.send_once(method, path, body, Some(&token)).await
    }

    async fn send_once(
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

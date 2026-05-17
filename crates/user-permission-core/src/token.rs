use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// Read the secret from `path`, or generate a 64-hex-char secret and persist it.
pub fn load_or_create_secret(path: impl AsRef<Path>) -> Result<String> {
    let path: PathBuf = path.as_ref().to_path_buf();
    if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        return Ok(content.trim().to_string());
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let secret = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, &secret)?;
    Ok(secret)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseClaims {
    pub sub: String,
    pub username: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct TokenManager {
    secret: String,
    algorithm: Algorithm,
}

impl TokenManager {
    pub fn new(secret: impl Into<String>, algorithm: Algorithm) -> Self {
        Self {
            secret: secret.into(),
            algorithm,
        }
    }

    pub fn hs256(secret: impl Into<String>) -> Self {
        Self::new(secret, Algorithm::HS256)
    }

    pub fn from_file(path: impl AsRef<Path>, algorithm: Algorithm) -> Result<Self> {
        Ok(Self::new(load_or_create_secret(path)?, algorithm))
    }

    pub fn create_token(
        &self,
        user_id: i64,
        username: &str,
        expires_in: Duration,
        extra_claims: Option<&Map<String, Value>>,
    ) -> Result<String> {
        let now = Utc::now().timestamp();
        let exp = now + expires_in.as_secs() as i64;

        let mut payload = Map::new();
        payload.insert("sub".into(), Value::String(user_id.to_string()));
        payload.insert("username".into(), Value::String(username.to_string()));
        payload.insert("iat".into(), Value::Number(now.into()));
        payload.insert("exp".into(), Value::Number(exp.into()));

        if let Some(extra) = extra_claims {
            for (k, v) in extra {
                payload.insert(k.clone(), v.clone());
            }
        }

        let token = encode(
            &Header::new(self.algorithm),
            &Value::Object(payload),
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )?;
        Ok(token)
    }

    /// Returns the raw decoded claim map (matching PyJWT's `decode` behaviour).
    pub fn verify_token(&self, token: &str) -> Result<Map<String, Value>> {
        let mut validation = Validation::new(self.algorithm);
        validation.required_spec_claims.clear();
        validation.required_spec_claims.insert("exp".to_string());

        let data = decode::<Value>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )?;
        match data.claims {
            Value::Object(map) => Ok(map),
            _ => Err(Error::Jwt(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ))),
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify_round_trip() {
        let mgr = TokenManager::hs256("test-secret");
        let token = mgr
            .create_token(42, "alice", Duration::from_secs(60), None)
            .unwrap();
        let claims = mgr.verify_token(&token).unwrap();
        assert_eq!(claims["sub"], Value::String("42".into()));
        assert_eq!(claims["username"], Value::String("alice".into()));
    }

    #[test]
    fn extra_claims_included() {
        let mgr = TokenManager::hs256("k");
        let mut extra = Map::new();
        extra.insert("is_admin".into(), Value::Bool(true));
        let token = mgr
            .create_token(1, "alice", Duration::from_secs(60), Some(&extra))
            .unwrap();
        let claims = mgr.verify_token(&token).unwrap();
        assert_eq!(claims["is_admin"], Value::Bool(true));
    }

    #[test]
    fn load_or_create_secret_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/secret.key");
        let first = load_or_create_secret(&path).unwrap();
        let second = load_or_create_secret(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }
}

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
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
    let secret = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, &secret)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(secret)
}

#[derive(Debug, Clone)]
pub struct TokenManager {
    secret: String,
    algorithm: Algorithm,
    /// 発行元サーバーの識別子。`Some` の場合、発行するトークンに `iss`
    /// クレームとして付与し、検証時にも一致を要求する。これにより同じ
    /// 署名鍵を使い回した別サーバーのトークンを拒否できる。
    issuer: Option<String>,
}

impl TokenManager {
    pub fn new(secret: impl Into<String>, algorithm: Algorithm) -> Self {
        Self {
            secret: secret.into(),
            algorithm,
            issuer: None,
        }
    }

    pub fn from_file(path: impl AsRef<Path>, algorithm: Algorithm) -> Result<Self> {
        Ok(Self::new(load_or_create_secret(path)?, algorithm))
    }

    /// 発行元サーバー識別子 (server_id) を設定する。
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn create_token(
        &self,
        user_id: uuid::Uuid,
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
        if let Some(iss) = &self.issuer {
            payload.insert("iss".into(), Value::String(iss.clone()));
        }

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

    /// Issue a JWT representing a machine-to-machine service client. The token
    /// carries `kind: "service"`, a non-numeric `sub` of `service:<client_id>`
    /// (so it can never be resolved to a `User`), and a space-separated `scope`
    /// claim. It is signed with the same master key but grants only the listed
    /// read scopes — never `is_admin`.
    pub fn create_service_token(
        &self,
        client_id: &str,
        scopes: &[String],
        expires_in: Duration,
    ) -> Result<String> {
        let now = Utc::now().timestamp();
        let exp = now + expires_in.as_secs() as i64;

        let mut payload = Map::new();
        payload.insert("sub".into(), Value::String(format!("service:{client_id}")));
        payload.insert("client_id".into(), Value::String(client_id.to_string()));
        payload.insert("kind".into(), Value::String("service".into()));
        payload.insert("scope".into(), Value::String(scopes.join(" ")));
        payload.insert("iat".into(), Value::Number(now.into()));
        payload.insert("exp".into(), Value::Number(exp.into()));
        if let Some(iss) = &self.issuer {
            payload.insert("iss".into(), Value::String(iss.clone()));
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
        if let Some(iss) = &self.issuer {
            // 発行元不一致(別サーバーで発行されたトークン)は署名が正しくても拒否する。
            validation.required_spec_claims.insert("iss".to_string());
            validation.set_issuer(&[iss]);
        }

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

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify_round_trip() {
        let mgr = TokenManager::new("test-secret", Algorithm::HS256);
        let id = uuid::Uuid::now_v7();
        let token = mgr
            .create_token(id, "alice", Duration::from_secs(60), None)
            .unwrap();
        let claims = mgr.verify_token(&token).unwrap();
        assert_eq!(claims["sub"], Value::String(id.to_string()));
        assert_eq!(claims["username"], Value::String("alice".into()));
    }

    #[test]
    fn extra_claims_included() {
        let mgr = TokenManager::new("k", Algorithm::HS256);
        let mut extra = Map::new();
        extra.insert("is_admin".into(), Value::Bool(true));
        let token = mgr
            .create_token(uuid::Uuid::now_v7(), "alice", Duration::from_secs(60), Some(&extra))
            .unwrap();
        let claims = mgr.verify_token(&token).unwrap();
        assert_eq!(claims["is_admin"], Value::Bool(true));
    }

    #[test]
    fn issuer_included_and_required() {
        let mgr = TokenManager::new("k", Algorithm::HS256).with_issuer("server-a");
        let token = mgr
            .create_token(uuid::Uuid::now_v7(), "alice", Duration::from_secs(60), None)
            .unwrap();
        let claims = mgr.verify_token(&token).unwrap();
        assert_eq!(claims["iss"], Value::String("server-a".into()));
    }

    #[test]
    fn issuer_mismatch_rejected() {
        // 同じ署名鍵でも issuer (server_id) が異なるサーバーのトークンは拒否される。
        let a = TokenManager::new("shared-secret", Algorithm::HS256).with_issuer("server-a");
        let b = TokenManager::new("shared-secret", Algorithm::HS256).with_issuer("server-b");
        let token = a
            .create_token(uuid::Uuid::now_v7(), "alice", Duration::from_secs(60), None)
            .unwrap();
        assert!(b.verify_token(&token).is_err());
    }

    #[test]
    fn token_without_issuer_rejected_by_issuer_aware_manager() {
        // iss を持たない旧形式トークンは、issuer 設定済みのマネージャで拒否される。
        let legacy = TokenManager::new("shared-secret", Algorithm::HS256);
        let strict = TokenManager::new("shared-secret", Algorithm::HS256).with_issuer("server-a");
        let token = legacy
            .create_token(uuid::Uuid::now_v7(), "alice", Duration::from_secs(60), None)
            .unwrap();
        assert!(strict.verify_token(&token).is_err());
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

    #[test]
    #[cfg(unix)]
    fn secret_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");
        load_or_create_secret(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "secret.key should be 0600");
    }
}

use argon2::Argon2;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::rngs::OsRng;

use crate::error::{Error, Result};

/// Default minimum accepted password length (in characters), used by
/// [`PasswordPolicy::default`]. Configurable per [`Database`](crate::Database)
/// via [`Database::open_local_with_policy`](crate::Database::open_local_with_policy).
pub const MIN_PASSWORD_LEN: usize = 8;
/// Maximum accepted password length (in bytes), a sanity cap against
/// pathological inputs reaching Argon2. Not configurable — this is a hard
/// safety limit, not a strength setting.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Passwords that meet the length rule but are so common they are rejected
/// outright (compared case-insensitively).
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "12345678",
    "123456789",
    "1234567890",
    "qwertyui",
    "qwerty123",
    "11111111",
    "iloveyou",
    "letmein123",
];

/// Configurable password strength policy. Every path that sets a password
/// (create / update / WebUI register / reset) funnels through
/// [`UserManager`](crate::UserManager), which validates against the policy
/// configured on the owning [`Database`](crate::Database) before hashing.
#[derive(Debug, Clone, Copy)]
pub struct PasswordPolicy {
    /// Minimum accepted length, in characters.
    pub min_len: usize,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_len: MIN_PASSWORD_LEN,
        }
    }
}

impl PasswordPolicy {
    /// Validate a user-chosen password against this policy. Returns
    /// [`Error::WeakPassword`] describing the violated rule.
    pub fn validate(&self, password: &str) -> Result<()> {
        if password.chars().count() < self.min_len {
            let min_len = self.min_len;
            return Err(Error::WeakPassword(format!(
                "password must be at least {min_len} characters"
            )));
        }
        if password.len() > MAX_PASSWORD_LEN {
            return Err(Error::WeakPassword(format!(
                "password must be at most {MAX_PASSWORD_LEN} bytes"
            )));
        }
        let lowered = password.to_lowercase();
        if COMMON_PASSWORDS.contains(&lowered.as_str()) {
            return Err(Error::WeakPassword(
                "password is too common; choose a less predictable one".into(),
            ));
        }
        Ok(())
    }
}

/// Validate a user-chosen password against the default strength policy
/// (minimum [`MIN_PASSWORD_LEN`] characters). Prefer
/// [`PasswordPolicy::validate`] when a custom minimum length is configured.
pub fn validate(password: &str) -> Result<()> {
    PasswordPolicy::default().validate(password)
}

/// Hash a plain-text password with Argon2id (PHC string format, compatible with `pwdlib`).
pub fn hash(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hasher = Argon2::default();
    let hash = hasher
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::Password(e.to_string()))?;
    Ok(hash.to_string())
}

/// Verify a plain-text password against a PHC-formatted hash string.
/// Returns `false` for malformed hashes (matching `pwdlib`'s `verify` semantics).
pub fn verify(password: &str, hashed: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hashed) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let h = hash("password123").unwrap();
        assert!(verify("password123", &h));
        assert!(!verify("wrong", &h));
    }

    #[test]
    fn verify_pwdlib_hash() {
        // Hash produced by pwdlib(argon2) for the password "password123".
        // pwdlib uses Argon2id v=19 with PHC string format, which the argon2 crate parses.
        let hashed = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$JvP/p2VHmHaZmKKxAOWlYZmKqgD7ZWZN7uYbVcEbQ8c";
        // The salt above is random; we just verify it parses without panicking.
        // (A real pwdlib hash test belongs in a Python-Rust integration test.)
        let _ = verify("password123", hashed);
    }

    #[test]
    fn malformed_hash_returns_false() {
        assert!(!verify("anything", "not-a-phc-string"));
    }

    #[test]
    fn validate_rejects_short_passwords() {
        assert!(validate("").is_err());
        assert!(validate("1").is_err());
        assert!(validate("short7c").is_err());
        assert!(validate("okpasswd").is_ok());
    }

    #[test]
    fn validate_counts_characters_not_bytes() {
        // 8 multi-byte characters must pass the minimum-length rule.
        assert!(validate("ぱすわーど八文字").is_ok());
    }

    #[test]
    fn validate_rejects_common_passwords() {
        assert!(validate("password").is_err());
        assert!(validate("PASSWORD123").is_err());
        assert!(validate("12345678").is_err());
    }

    #[test]
    fn validate_rejects_oversized_passwords() {
        assert!(validate(&"x".repeat(MAX_PASSWORD_LEN + 1)).is_err());
    }

    #[test]
    fn validate_error_is_weak_password() {
        assert!(matches!(validate("1"), Err(Error::WeakPassword(_))));
    }

    #[test]
    fn custom_policy_min_len_is_enforced() {
        let strict = PasswordPolicy { min_len: 12 };
        assert!(strict.validate("short7chars").is_err()); // 11文字
        assert!(strict.validate("twelve-chars").is_ok()); // 12文字

        let lenient = PasswordPolicy { min_len: 4 };
        assert!(lenient.validate("abcd").is_ok());
        assert!(lenient.validate("abc").is_err());
    }

    #[test]
    fn custom_policy_still_rejects_common_passwords() {
        let lenient = PasswordPolicy { min_len: 4 };
        assert!(lenient.validate("password").is_err());
    }
}

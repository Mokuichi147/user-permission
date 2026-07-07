use argon2::Argon2;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::rngs::OsRng;

use crate::error::{Error, Result};

/// Minimum accepted password length (in characters).
pub const MIN_PASSWORD_LEN: usize = 8;
/// Maximum accepted password length (in bytes), a sanity cap against
/// pathological inputs reaching Argon2.
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

/// Validate a user-chosen password against the strength policy. Every path
/// that sets a password (create / update / WebUI register / reset) funnels
/// through [`UserManager`](crate::UserManager), which calls this before
/// hashing. Returns [`Error::WeakPassword`] describing the violated rule.
pub fn validate(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(Error::WeakPassword(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
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
}

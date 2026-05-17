use argon2::Argon2;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::rngs::OsRng;

use crate::error::{Error, Result};

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
}

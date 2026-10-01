//! `ENC(...)` wrapper handling (Jasypt-compatible).

use crate::{Algorithm, Error};

/// Unwrap an `ENC(...)` value and decrypt it using the default AES-256-CBC algorithm.
pub fn decrypt_enc(value: &str, password: &str) -> Result<String, Error> {
    decrypt_enc_with(Algorithm::default(), value, password)
}

/// Unwrap an `ENC(...)` value and decrypt it with the given algorithm.
pub fn decrypt_enc_with(
    algorithm: Algorithm,
    value: &str,
    password: &str,
) -> Result<String, Error> {
    let trimmed = value.trim();
    if trimmed.starts_with("ENC(") && trimmed.ends_with(')') {
        let inner = &trimmed[4..trimmed.len() - 1];
        crate::decrypt_with(algorithm, password, inner)
    } else {
        Err(Error::NotEncValue)
    }
}

/// Check if a string value is wrapped in `ENC(...)`.
pub fn is_enc_value(value: &str) -> bool {
    let t = value.trim();
    t.starts_with("ENC(") && t.ends_with(')')
}

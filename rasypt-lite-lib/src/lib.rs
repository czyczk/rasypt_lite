//! Jasypt-compatible PBEWithHMACSHA512AndAES_256 encryption/decryption.
//!
//! Binary format (compatible with jasypt-spring-boot 3.x defaults):
//!   [salt: 16 bytes][iv: 16 bytes][ciphertext (AES-256-CBC/PKCS7)]
//!
//! Key derivation: PBKDF2-HMAC-SHA512, 1000 iterations, 32-byte key.
//! String encoding: Base64 (standard).

use std::string;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha512;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const KEY_SIZE: usize = 32; // AES-256
const DEFAULT_ITERATIONS: u32 = 1000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Ciphertext too short")]
    CiphertextTooShort,
    #[error("Failed to decode base64: {0}")]
    FailedToDecodeBase64(base64::DecodeError),
    #[error("Failed to decrypt (bad padding or wrong password): {0}")]
    FailedToDecryptDueToBadPaddingOrWrongPassword(aes::cipher::block_padding::UnpadError),
    #[error("Invalid decryption result: {0}")]
    InvalidDecryptionResult(string::FromUtf8Error),
    #[error("Not an ENC(...) value")]
    NotEncValue,
}

/// Derive a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA512.
fn derive_key(password: &str, salt: &[u8], iterations: u32) -> [u8; KEY_SIZE] {
    let normalized: String = password.nfc().collect();
    let mut normalized_bytes = normalized.into_bytes();
    let mut key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha512>(&normalized_bytes, salt, iterations, &mut key);
    // zeroize normalized password bytes as soon as possible
    normalized_bytes.zeroize();
    key
}

/// Encrypt plaintext with the given password. Returns Base64-encoded ciphertext.
pub fn encrypt(plaintext: &str, password: &str) -> String {
    encrypt_with_iterations(plaintext, password, DEFAULT_ITERATIONS)
}

/// Encrypt with a custom iteration count.
pub fn encrypt_with_iterations(plaintext: &str, password: &str, iterations: u32) -> String {
    let mut rng = rand::rng();
    let mut salt = [0u8; SALT_SIZE];
    rng.fill_bytes(&mut salt);
    let mut iv = [0u8; IV_SIZE];
    rng.fill_bytes(&mut iv);
    let mut key = derive_key(password, &salt, iterations);
    let encryptor = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();
    // zero out derived key material immediately after use
    key.zeroize();
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
    let mut output = Vec::with_capacity(SALT_SIZE + IV_SIZE + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);
    B64.encode(&output)
}

/// Decrypt a Base64-encoded ciphertext produced by Jasypt (or this library).
pub fn decrypt(encoded: &str, password: &str) -> Result<String, Error> {
    decrypt_with_iterations(encoded, password, DEFAULT_ITERATIONS)
}

/// Decrypt with a custom iteration count.
pub fn decrypt_with_iterations(
    encoded: &str,
    password: &str,
    iterations: u32,
) -> Result<String, Error> {
    let data = B64
        .decode(encoded)
        .map_err(|e| Error::FailedToDecodeBase64(e))?;
    if data.len() < SALT_SIZE + IV_SIZE + 1 {
        return Err(Error::CiphertextTooShort);
    }
    let salt = &data[..SALT_SIZE];
    let iv = &data[SALT_SIZE..SALT_SIZE + IV_SIZE];
    let ciphertext = &data[SALT_SIZE + IV_SIZE..];
    let mut key = derive_key(password, salt, iterations);
    let decryptor = Aes256CbcDec::new_from_slices(&key, iv).unwrap();
    // zero out derived key material as soon as possible
    key.zeroize();
    let plaintext = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&mut ciphertext.to_vec())
        .map_err(|e| Error::FailedToDecryptDueToBadPaddingOrWrongPassword(e))?;
    String::from_utf8(plaintext).map_err(|e| Error::InvalidDecryptionResult(e))
}

/// Unwrap an `ENC(...)` value and decrypt it.
pub fn decrypt_enc(value: &str, password: &str) -> Result<String, Error> {
    let trimmed = value.trim();
    if trimmed.starts_with("ENC(") && trimmed.ends_with(')') {
        let inner = &trimmed[4..trimmed.len() - 1];
        decrypt(inner, password)
    } else {
        Err(Error::NotEncValue)
    }
}

/// Check if a string value is wrapped in `ENC(...)`.
pub fn is_enc_value(value: &str) -> bool {
    let t = value.trim();
    t.starts_with("ENC(") && t.ends_with(')')
}

/// Clear a `String`'s heap buffer by zeroizing its bytes and replacing it with an empty string.
pub fn clear_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    bytes.zeroize();
}

/// Clear an `Option<String>` by zeroizing the inner string (if present) and setting it to `None`.
pub fn clear_option_string(o: &mut Option<String>) {
    if let Some(s) = o.take() {
        let mut bytes = s.into_bytes();
        bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let password = "mySecretPassword";
        let plaintext = "Hello, Jasypt!";
        let encrypted = encrypt(plaintext, password);
        let decrypted = decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_enc_wrapper() {
        let password = "test";
        let plaintext = "secret";
        let encrypted = encrypt(plaintext, password);
        let wrapped = format!("ENC({})", encrypted);
        let decrypted = decrypt_enc(&wrapped, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_encryptions_differ() {
        let e1 = encrypt("hello", "pass");
        let e2 = encrypt("hello", "pass");
        assert_ne!(e1, e2); // random salt & IV
    }

    #[test]
    fn clear_string_works() {
        let mut s = String::from("secret");
        clear_string(&mut s);
        assert_eq!(s, "");
    }

    #[test]
    fn clear_option_string_works() {
        let mut o = Some(String::from("secret"));
        clear_option_string(&mut o);
        assert_eq!(o, None);
    }

    #[test]
    fn rejects_too_short_ciphertext() {
        // 32 bytes decodes successfully but is too short for [salt(16)][iv(16)][ciphertext(>=1)].
        let too_short = B64.encode([0u8; SALT_SIZE + IV_SIZE]);
        let err = decrypt(&too_short, "password").unwrap_err();
        assert!(matches!(err, Error::CiphertextTooShort));
    }
}

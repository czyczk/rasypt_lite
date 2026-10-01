//! Password-based encryption supporting multiple algorithms:
//! - PBEWithHMACSHA512AndAES_256 (Jasypt-compatible, default)
//! - PBEWithHMACSM3AndSM4_GCM (SM4-GCM AEAD with HMAC-SM3 key commitment)
//! - PBEWithHMACSM3AndSM4_CBC (SM4-CBC with Encrypt-then-HMAC-SM3, GM/T 0091)
//!
//! All decryption failures produce the same single generic error.
//! Constant-time comparisons are used where required (MAC and tag; the
//! SM4-CBC padding is protected by Encrypt-then-MAC).

mod algorithm;
mod constants;
mod enc;
mod error;
mod kdf;
mod memory;
mod sm4;

pub use algorithm::Algorithm;
pub use enc::{decrypt_enc, decrypt_enc_with, is_enc_value};
pub use error::Error;
pub use memory::{clear_option_string, clear_string};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use zeroize::Zeroize;

use constants::{
    HMAC_SM3_OUTPUT_SIZE, SALT_SIZE, SM4_BLOCK_SIZE, SM4_GCM_NONCE_SIZE, SM4_GCM_TAG_SIZE,
};
use kdf::{derive_aes_key, derive_sm4_keys, random_bytes};
use sm4::{hmac_sm3_sign, hmac_sm3_verify, sm4_cbc_decrypt, sm4_cbc_encrypt};
use sm4::{sm4_gcm_decrypt, sm4_gcm_encrypt};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

// ── Public API ─────────────────────────────────────────────────────

/// Encrypt with the default algorithm (AES-256-CBC, Jasypt-compatible).
pub fn encrypt(password: &str, plaintext: &str) -> String {
    encrypt_with(Algorithm::default(), password, plaintext)
}

/// Decrypt with the default algorithm (AES-256-CBC, Jasypt-compatible).
pub fn decrypt(password: &str, encoded: &str) -> Result<String, Error> {
    decrypt_with(Algorithm::default(), password, encoded)
}

/// Encrypt with a specific algorithm and default iteration count.
pub fn encrypt_with(algorithm: Algorithm, password: &str, plaintext: &str) -> String {
    let iterations = algorithm.default_iterations();
    encrypt_with_iterations(algorithm, password, plaintext, iterations)
}

/// Decrypt with a specific algorithm and default iteration count.
pub fn decrypt_with(algorithm: Algorithm, password: &str, encoded: &str) -> Result<String, Error> {
    let iterations = algorithm.default_iterations();
    decrypt_with_iterations(algorithm, password, encoded, iterations)
}

/// Encrypt with a specific algorithm and custom iteration count.
pub fn encrypt_with_iterations(
    algorithm: Algorithm,
    password: &str,
    plaintext: &str,
    iterations: u32,
) -> String {
    let mut rng = rand::rng();
    match algorithm {
        Algorithm::PBEWithHMACSHA512AndAES_256 => {
            let salt = random_bytes::<SALT_SIZE>(&mut rng);
            let iv = random_bytes::<SALT_SIZE>(&mut rng);

            let mut key = derive_aes_key(password, &salt, iterations);
            let encryptor = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();
            key.zeroize();
            let ciphertext = encryptor.encrypt_padded_vec::<Pkcs7>(plaintext.as_bytes());

            let mut output = Vec::with_capacity(SALT_SIZE + SALT_SIZE + ciphertext.len());
            output.extend_from_slice(&salt);
            output.extend_from_slice(&iv);
            output.extend_from_slice(&ciphertext);
            B64.encode(&output)
        }
        Algorithm::PBEWithHMACSM3AndSM4_GCM => {
            let salt = random_bytes::<SALT_SIZE>(&mut rng);
            let nonce = random_bytes::<SM4_GCM_NONCE_SIZE>(&mut rng);

            let dk = derive_sm4_keys(password, &salt, iterations);
            let (ciphertext, tag) =
                sm4_gcm_encrypt(dk.encryption_key(), &nonce, &salt, plaintext.as_bytes());
            let commitment = hmac_sm3_sign(dk.mac_key(), &[&salt, &nonce, &ciphertext, &tag]);
            drop(dk);

            let mut output = Vec::with_capacity(
                SALT_SIZE
                    + SM4_GCM_NONCE_SIZE
                    + ciphertext.len()
                    + SM4_GCM_TAG_SIZE
                    + HMAC_SM3_OUTPUT_SIZE,
            );
            output.extend_from_slice(&salt);
            output.extend_from_slice(&nonce);
            output.extend_from_slice(&ciphertext);
            output.extend_from_slice(&tag);
            output.extend_from_slice(&commitment);
            B64.encode(&output)
        }
        Algorithm::PBEWithHMACSM3AndSM4_CBC => {
            let salt = random_bytes::<SALT_SIZE>(&mut rng);
            let iv = random_bytes::<SM4_BLOCK_SIZE>(&mut rng);

            let dk = derive_sm4_keys(password, &salt, iterations);
            let (ciphertext, mac) =
                sm4_cbc_encrypt(dk.encryption_key(), dk.mac_key(), &iv, plaintext.as_bytes());
            drop(dk);

            let mut output = Vec::with_capacity(
                SALT_SIZE + SM4_BLOCK_SIZE + ciphertext.len() + HMAC_SM3_OUTPUT_SIZE,
            );
            output.extend_from_slice(&salt);
            output.extend_from_slice(&iv);
            output.extend_from_slice(&ciphertext);
            output.extend_from_slice(&mac);
            B64.encode(&output)
        }
    }
}

/// Decrypt with a specific algorithm and custom iteration count.
pub fn decrypt_with_iterations(
    algorithm: Algorithm,
    password: &str,
    encoded: &str,
    iterations: u32,
) -> Result<String, Error> {
    let data = B64.decode(encoded).map_err(Error::FailedToDecodeBase64)?;

    match algorithm {
        Algorithm::PBEWithHMACSHA512AndAES_256 => {
            if data.len() < SALT_SIZE + SALT_SIZE + 1 {
                return Err(Error::CiphertextTooShort);
            }
            let salt = &data[..SALT_SIZE];
            let iv = &data[SALT_SIZE..SALT_SIZE + SALT_SIZE];
            let ciphertext = &data[SALT_SIZE + SALT_SIZE..];

            let mut key = derive_aes_key(password, salt, iterations);
            let decryptor = Aes256CbcDec::new_from_slices(&key, iv).unwrap();
            key.zeroize();
            let plaintext = decryptor
                .decrypt_padded_vec::<Pkcs7>(ciphertext)
                .map_err(Error::FailedToDecryptDueToBadPaddingOrWrongPassword)?;
            String::from_utf8(plaintext).map_err(Error::InvalidDecryptionResult)
        }
        Algorithm::PBEWithHMACSM3AndSM4_GCM => {
            let min_len = SALT_SIZE + SM4_GCM_NONCE_SIZE + SM4_GCM_TAG_SIZE + HMAC_SM3_OUTPUT_SIZE;
            if data.len() < min_len {
                return Err(Error::CiphertextTooShort);
            }
            let salt: &[u8; SALT_SIZE] = data[..SALT_SIZE].try_into().unwrap();
            let nonce: &[u8; SM4_GCM_NONCE_SIZE] = data[SALT_SIZE..SALT_SIZE + SM4_GCM_NONCE_SIZE]
                .try_into()
                .unwrap();
            let commitment_start = data.len() - HMAC_SM3_OUTPUT_SIZE;
            let received_commitment: &[u8; HMAC_SM3_OUTPUT_SIZE] =
                data[commitment_start..].try_into().unwrap();
            let tag_start = commitment_start - SM4_GCM_TAG_SIZE;
            let tag: &[u8; SM4_GCM_TAG_SIZE] =
                data[tag_start..commitment_start].try_into().unwrap();
            let ciphertext = &data[SALT_SIZE + SM4_GCM_NONCE_SIZE..tag_start];

            let dk = derive_sm4_keys(password, salt, iterations);

            if !hmac_sm3_verify(
                dk.mac_key(),
                &[salt, nonce, ciphertext, tag],
                received_commitment,
            ) {
                return Err(Error::DecryptionFailed);
            }
            let plaintext = sm4_gcm_decrypt(dk.encryption_key(), nonce, salt, ciphertext, tag)?;
            String::from_utf8(plaintext).map_err(|_| Error::DecryptionFailed)
        }
        Algorithm::PBEWithHMACSM3AndSM4_CBC => {
            let min_len = SALT_SIZE + SM4_BLOCK_SIZE + 1 + HMAC_SM3_OUTPUT_SIZE;
            if data.len() < min_len {
                return Err(Error::CiphertextTooShort);
            }
            let salt: &[u8; SALT_SIZE] = data[..SALT_SIZE].try_into().unwrap();
            let iv: &[u8; SM4_BLOCK_SIZE] = data[SALT_SIZE..SALT_SIZE + SM4_BLOCK_SIZE]
                .try_into()
                .unwrap();
            let mac_start = data.len() - HMAC_SM3_OUTPUT_SIZE;
            let expected_mac: &[u8; HMAC_SM3_OUTPUT_SIZE] = data[mac_start..].try_into().unwrap();
            let ciphertext = &data[SALT_SIZE + SM4_BLOCK_SIZE..mac_start];

            let dk = derive_sm4_keys(password, salt, iterations);

            let plaintext = sm4_cbc_decrypt(
                dk.encryption_key(),
                dk.mac_key(),
                iv,
                ciphertext,
                expected_mac,
            )?;
            String::from_utf8(plaintext).map_err(|_| Error::DecryptionFailed)
        }
    }
}

#[cfg(test)]
mod tests;

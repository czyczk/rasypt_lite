//! Password normalization and PBKDF2-based key derivation.

use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha512;
use sm3::Sm3;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::constants::{AES_KEY_SIZE, HMAC_SM3_OUTPUT_SIZE, SM4_KEY_SIZE};

fn normalize_password(password: &str) -> Vec<u8> {
    password.nfc().collect::<String>().into_bytes()
}

pub(crate) fn derive_aes_key(password: &str, salt: &[u8], iterations: u32) -> [u8; AES_KEY_SIZE] {
    let mut nfc_bytes = normalize_password(password);
    let mut key = [0u8; AES_KEY_SIZE];
    pbkdf2_hmac::<Sha512>(&nfc_bytes, salt, iterations, &mut key);
    nfc_bytes.zeroize();
    key
}

pub(crate) fn derive_sm4_keys(password: &str, salt: &[u8], iterations: u32) -> Sm4DerivedKeys {
    let mut nfc_bytes = normalize_password(password);
    let mut dk = [0u8; Sm4DerivedKeys::LEN];
    pbkdf2_hmac::<Sm3>(&nfc_bytes, salt, iterations, &mut dk);
    nfc_bytes.zeroize();
    Sm4DerivedKeys { dk }
}

/// PBKDF2-HMAC-SM3 output for the SM4 algorithms, split into an SM4
/// encryption key and an HMAC-SM3 authentication key.
pub(crate) struct Sm4DerivedKeys {
    dk: [u8; Self::LEN],
}

impl Sm4DerivedKeys {
    pub(crate) const LEN: usize = SM4_KEY_SIZE + HMAC_SM3_OUTPUT_SIZE; // 48

    pub(crate) fn encryption_key(&self) -> &[u8; SM4_KEY_SIZE] {
        self.dk[..SM4_KEY_SIZE].try_into().unwrap()
    }

    pub(crate) fn mac_key(&self) -> &[u8; HMAC_SM3_OUTPUT_SIZE] {
        self.dk[SM4_KEY_SIZE..].try_into().unwrap()
    }
}

impl Drop for Sm4DerivedKeys {
    fn drop(&mut self) {
        self.dk.zeroize();
    }
}

/// Fill a fixed-size array with cryptographically secure random bytes.
pub(crate) fn random_bytes<const N: usize>(rng: &mut impl Rng) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

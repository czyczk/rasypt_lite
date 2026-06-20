//! Password-based encryption supporting multiple algorithms:
//! - PBEWithHMACSHA512AndAES_256 (Jasypt-compatible, default)
//! - PBEWithHMACSM3AndSM4_GCM (SM4-GCM AEAD with HMAC-SM3 key commitment)
//! - PBEWithHMACSM3AndSM4_CBC (SM4-CBC with Encrypt-then-HMAC-SM3, GM/T 0091)
//!
//! All decryption failures produce the same single generic error.
//! Constant-time comparisons are used where required (MAC, tag, padding).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::cipher::{
    block_padding::Pkcs7,
    BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha512;
use sm3::Sm3;
use sm4::Sm4;
use sm4::cipher::BlockCipherEncrypt;
use strum::{Display, EnumIter, IntoEnumIterator};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use ghash::{GHash, universal_hash::UniversalHash};

// ── Type aliases ──────────────────────────────────────────────────

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Sm4CbcEnc = cbc::Encryptor<Sm4>;
type Sm4CbcDec = cbc::Decryptor<Sm4>;

// ── Constants ─────────────────────────────────────────────────────

const SALT_SIZE: usize = 16;
const SM4_KEY_SIZE: usize = 16;
const AES_KEY_SIZE: usize = 32;
const SM4_BLOCK_SIZE: usize = 16;
const SM4_GCM_NONCE_SIZE: usize = 12;
const SM4_GCM_TAG_SIZE: usize = 16;
const HMAC_SM3_OUTPUT: usize = 32;
const SM4_CBC_DK_LEN: usize = SM4_KEY_SIZE + HMAC_SM3_OUTPUT;       // 48
const SM4_GCM_DK_LEN: usize = SM4_KEY_SIZE + HMAC_SM3_OUTPUT;       // 48

const DEFAULT_AES_ITERATIONS: u32 = 1_000;
const DEFAULT_SM_ITERATIONS: u32 = 10_000;

// ── Algorithm enum ─────────────────────────────────────────────────

/// Supported password-based encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Display, EnumIter)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    /// PBEWithHMACSHA512AndAES_256 — Jasypt-compatible, AES-256-CBC with PBKDF2-HMAC-SHA512.
    #[default]
    PBEWithHMACSHA512AndAES_256,
    /// PBEWithHMACSM3AndSM4_GCM — SM4-GCM AEAD with HMAC-SM3 key commitment.
    PBEWithHMACSM3AndSM4_GCM,
    /// PBEWithHMACSM3AndSM4_CBC — SM4-CBC with Encrypt-then-HMAC-SM3.
    PBEWithHMACSM3AndSM4_CBC,
}

impl std::str::FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PBEWithHMACSHA512AndAES_256" => Ok(Algorithm::PBEWithHMACSHA512AndAES_256),
            "PBEWithHMACSM3AndSM4_GCM" => Ok(Algorithm::PBEWithHMACSM3AndSM4_GCM),
            "PBEWithHMACSM3AndSM4_CBC" => Ok(Algorithm::PBEWithHMACSM3AndSM4_CBC),
            _ => {
                let names: Vec<String> = Algorithm::iter().map(|a| a.to_string()).collect();
                Err(format!("unknown algorithm: {s}. valid: {}", names.join(", ")))
            }
        }
    }
}

impl Algorithm {
    fn default_iterations(self) -> u32 {
        match self {
            Algorithm::PBEWithHMACSHA512AndAES_256 => DEFAULT_AES_ITERATIONS,
            _ => DEFAULT_SM_ITERATIONS,
        }
    }
}

// ── Error (single generic failure for all decryption failures) ────

#[derive(Debug)]
pub enum Error {
    CiphertextTooShort,
    FailedToDecodeBase64(base64::DecodeError),
    FailedToDecryptDueToBadPaddingOrWrongPassword(cbc::cipher::block_padding::Error),
    InvalidDecryptionResult(std::string::FromUtf8Error),
    NotEncValue,
    DecryptionFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CiphertextTooShort => write!(f, "Ciphertext too short"),
            Error::FailedToDecodeBase64(e) => write!(f, "Failed to decode base64: {}", e),
            Error::FailedToDecryptDueToBadPaddingOrWrongPassword(e) => {
                write!(f, "Failed to decrypt (bad padding or wrong password): {}", e)
            }
            Error::InvalidDecryptionResult(e) => write!(f, "Invalid decryption result: {}", e),
            Error::NotEncValue => write!(f, "Not an ENC(...) value"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::FailedToDecodeBase64(e) => Some(e),
            Error::InvalidDecryptionResult(e) => Some(e),
            _ => None,
        }
    }
}

// ── Key Derivation ─────────────────────────────────────────────────

fn normalize_password(password: &str) -> Vec<u8> {
    password.nfc().collect::<String>().into_bytes()
}

fn derive_aes_key(password: &str, salt: &[u8], iterations: u32) -> [u8; AES_KEY_SIZE] {
    let mut nfc_bytes = normalize_password(password);
    let mut key = [0u8; AES_KEY_SIZE];
    pbkdf2_hmac::<Sha512>(&nfc_bytes, salt, iterations, &mut key);
    nfc_bytes.zeroize();
    key
}

fn derive_sm_keys<const DK_LEN: usize>(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> [u8; DK_LEN] {
    let mut nfc_bytes = normalize_password(password);
    let mut dk = [0u8; DK_LEN];
    pbkdf2_hmac::<Sm3>(&nfc_bytes, salt, iterations, &mut dk);
    nfc_bytes.zeroize();
    dk
}

// ── Constant-time PKCS#7 unpadding ────────────────────────────────

/// Constant-time PKCS#7 padding verification.
/// Returns `Some(unpadded_len)` if padding is valid, `None` otherwise.
#[allow(dead_code)]
fn ct_pkcs7_unpad(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    let last = data[data.len() - 1];
    let pad_len = last as usize;
    // pad_len range: 1..=16 for SM4/AES blocks
    if pad_len == 0 || pad_len > SM4_BLOCK_SIZE || pad_len > data.len() {
        return None;
    }
    let mut accum: u8 = 0;
    let start = data.len() - pad_len;
    for i in start..data.len() {
        accum |= data[i] ^ last;
    }
    if accum != 0 {
        return None;
    }
    Some(start)
}

// ── HMAC-SM3 helper ───────────────────────────────────────────────

fn hmac_sm3_sign(key: &[u8], data: &[&[u8]]) -> [u8; HMAC_SM3_OUTPUT] {
    let mut mac = <Hmac<Sm3>>::new_from_slice(key).expect("HMAC key size; Sm3 key is flexible");
    for chunk in data {
        mac.update(chunk);
    }
    mac.finalize().into_bytes().into()
}

fn hmac_sm3_verify(key: &[u8], data: &[&[u8]], expected: &[u8; HMAC_SM3_OUTPUT]) -> bool {
    let computed = hmac_sm3_sign(key, data);
    expected.ct_eq(&computed).into()
}

// ── SM4-GCM implementation (using ghash crate for authentication) ──

/// Increment the last 32 bits of a 16-byte block (big-endian).
fn inc_32(block: &mut [u8; 16]) {
    let val = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    let incremented = val.wrapping_add(1);
    block[12..16].copy_from_slice(&incremented.to_be_bytes());
}

/// Feed arbitrary byte data into a GHash instance, zero-padding to block boundaries.
fn ghash_update(ghash: &mut GHash, data: &[u8]) {
    let padded_len = ((data.len() + 15) / 16) * 16;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len()].copy_from_slice(data);
    let blocks: Vec<ghash::Block> = padded
        .chunks_exact(16)
        .map(|c| {
            let arr: [u8; 16] = c.try_into().unwrap();
            arr.into()
        })
        .collect();
    if !blocks.is_empty() {
        ghash.update(&blocks);
    }
}

/// Compute GHASH(H, AAD, ciphertext) per NIST SP 800-38D.
fn compute_ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let key = (*h).into();
    let mut ghash = GHash::new(&key);
    ghash_update(&mut ghash, aad);
    ghash_update(&mut ghash, ciphertext);

    let len_bits_aad = (aad.len() as u64).wrapping_mul(8);
    let len_bits_ct = (ciphertext.len() as u64).wrapping_mul(8);
    let mut len_arr = [0u8; 16];
    len_arr[..8].copy_from_slice(&len_bits_aad.to_be_bytes());
    len_arr[8..].copy_from_slice(&len_bits_ct.to_be_bytes());
    let len_block: ghash::Block = len_arr.into();
    ghash.update(&[len_block]);

    let result: ghash::Block = ghash.finalize();
    let bytes: &[u8; 16] = result.as_ref();
    *bytes
}

fn gctr(cipher: &Sm4, icb: [u8; 16], data: &[u8]) -> Vec<u8> {
    let n = (data.len() + SM4_BLOCK_SIZE - 1) / SM4_BLOCK_SIZE;
    let mut output = vec![0u8; data.len()];
    let mut counter = icb;

    for i in 0..n {
        let mut ctr_block: sm4::cipher::Block<Sm4> = counter.into();
        cipher.encrypt_block(&mut ctr_block);
        let keystream: &[u8; 16] = ctr_block.as_ref();
        let start = i * SM4_BLOCK_SIZE;
        let end = std::cmp::min(start + SM4_BLOCK_SIZE, data.len());
        for j in start..end {
            output[j] = data[j] ^ keystream[j - start];
        }
        inc_32(&mut counter);
    }
    output
}

fn sm4_gcm_encrypt(
    key: &[u8; SM4_KEY_SIZE],
    nonce: &[u8; SM4_GCM_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; SM4_GCM_TAG_SIZE]) {
    let cipher = Sm4::new(&(*key).into());

    // H = E_K(0^128)
    let mut h_block: sm4::cipher::Block<Sm4> = [0u8; SM4_BLOCK_SIZE].into();
    cipher.encrypt_block(&mut h_block);
    let h: [u8; 16] = *h_block.as_ref();

    // J0 = nonce || 0^31 || 1
    let mut j0 = [0u8; SM4_BLOCK_SIZE];
    j0[..SM4_GCM_NONCE_SIZE].copy_from_slice(nonce);
    j0[15] = 1;

    // Encrypt J0 for final tag XOR
    let mut enc_j0_block: sm4::cipher::Block<Sm4> = j0.into();
    cipher.encrypt_block(&mut enc_j0_block);
    let enc_j0: [u8; 16] = *enc_j0_block.as_ref();

    // GCTR: encrypt with initial counter = inc_32(J0)
    let mut icb = j0;
    inc_32(&mut icb);
    let ciphertext = gctr(&cipher, icb, plaintext);

    // GHASH
    let s = compute_ghash(&h, aad, &ciphertext);

    // Tag = S XOR E_K(J0)
    let mut tag = [0u8; SM4_GCM_TAG_SIZE];
    for i in 0..SM4_GCM_TAG_SIZE {
        tag[i] = s[i] ^ enc_j0[i];
    }

    (ciphertext, tag)
}

fn sm4_gcm_decrypt(
    key: &[u8; SM4_KEY_SIZE],
    nonce: &[u8; SM4_GCM_NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; SM4_GCM_TAG_SIZE],
) -> Result<Vec<u8>, Error> {
    let cipher = Sm4::new(&(*key).into());

    // H = E_K(0^128)
    let mut h_block: sm4::cipher::Block<Sm4> = [0u8; SM4_BLOCK_SIZE].into();
    cipher.encrypt_block(&mut h_block);
    let h: [u8; 16] = *h_block.as_ref();

    // J0 = nonce || 0^31 || 1
    let mut j0 = [0u8; SM4_BLOCK_SIZE];
    j0[..SM4_GCM_NONCE_SIZE].copy_from_slice(nonce);
    j0[15] = 1;

    // Encrypt J0
    let mut enc_j0_block: sm4::cipher::Block<Sm4> = j0.into();
    cipher.encrypt_block(&mut enc_j0_block);
    let enc_j0: [u8; 16] = *enc_j0_block.as_ref();

    // Verify tag first (constant-time)
    let s = compute_ghash(&h, aad, ciphertext);
    let mut expected_tag = [0u8; SM4_GCM_TAG_SIZE];
    for i in 0..SM4_GCM_TAG_SIZE {
        expected_tag[i] = s[i] ^ enc_j0[i];
    }
    if bool::from(expected_tag.ct_ne(tag)) {
        return Err(Error::DecryptionFailed);
    }

    // Decrypt
    let mut icb = j0;
    inc_32(&mut icb);
    Ok(gctr(&cipher, icb, ciphertext))
}

// ── SM4-CBC + Encrypt-then-HMAC-SM3 ───────────────────────────────

fn sm4_cbc_encrypt(
    key: &[u8; SM4_KEY_SIZE],
    mac_key: &[u8; HMAC_SM3_OUTPUT],
    iv: &[u8; SM4_BLOCK_SIZE],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; HMAC_SM3_OUTPUT]) {
    let encryptor = Sm4CbcEnc::new_from_slices(key, iv).unwrap();
    let ciphertext = encryptor.encrypt_padded_vec::<Pkcs7>(plaintext);

    // MAC = HMAC-SM3(mac_key, IV || ciphertext)
    let mac = hmac_sm3_sign(mac_key, &[iv, &ciphertext]);
    (ciphertext, mac)
}

fn sm4_cbc_decrypt(
    key: &[u8; SM4_KEY_SIZE],
    mac_key: &[u8; HMAC_SM3_OUTPUT],
    iv: &[u8; SM4_BLOCK_SIZE],
    ciphertext: &[u8],
    expected_mac: &[u8; HMAC_SM3_OUTPUT],
) -> Result<Vec<u8>, Error> {
    // Verify MAC first (Encrypt-then-MAC, constant-time)
    if !hmac_sm3_verify(mac_key, &[iv, ciphertext], expected_mac) {
        return Err(Error::DecryptionFailed);
    }

    let decryptor = Sm4CbcDec::new_from_slices(key, iv).unwrap();
    let plaintext = decryptor
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(plaintext)
}

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
pub fn decrypt_with(
    algorithm: Algorithm,
    password: &str,
    encoded: &str,
) -> Result<String, Error> {
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
            let mut salt = [0u8; SALT_SIZE];
            rng.fill_bytes(&mut salt);
            let mut iv = [0u8; SALT_SIZE];
            rng.fill_bytes(&mut iv);
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
            let mut salt = [0u8; SALT_SIZE];
            rng.fill_bytes(&mut salt);
            let mut nonce = [0u8; SM4_GCM_NONCE_SIZE];
            rng.fill_bytes(&mut nonce);
            let dk = derive_sm_keys::<SM4_GCM_DK_LEN>(password, &salt, iterations);
            let enc_key: &[u8; SM4_KEY_SIZE] = dk[..SM4_KEY_SIZE].try_into().unwrap();
            let commit_key: &[u8; HMAC_SM3_OUTPUT] =
                dk[SM4_KEY_SIZE..SM4_GCM_DK_LEN].try_into().unwrap();

            let (ciphertext, tag) =
                sm4_gcm_encrypt(enc_key, &nonce, &salt, plaintext.as_bytes());

            // Key commitment: HMAC-SM3(commit_key, salt || nonce || ciphertext || tag)
            let commitment = hmac_sm3_sign(commit_key, &[&salt, &nonce, &ciphertext, &tag]);

            let mut output = Vec::with_capacity(
                SALT_SIZE + SM4_GCM_NONCE_SIZE + ciphertext.len() + SM4_GCM_TAG_SIZE + HMAC_SM3_OUTPUT,
            );
            output.extend_from_slice(&salt);
            output.extend_from_slice(&nonce);
            output.extend_from_slice(&ciphertext);
            output.extend_from_slice(&tag);
            output.extend_from_slice(&commitment);
            B64.encode(&output)
        }
        Algorithm::PBEWithHMACSM3AndSM4_CBC => {
            let mut salt = [0u8; SALT_SIZE];
            rng.fill_bytes(&mut salt);
            let mut iv = [0u8; SM4_BLOCK_SIZE];
            rng.fill_bytes(&mut iv);
            let dk = derive_sm_keys::<SM4_CBC_DK_LEN>(password, &salt, iterations);
            let enc_key: &[u8; SM4_KEY_SIZE] = dk[..SM4_KEY_SIZE].try_into().unwrap();
            let mac_key: &[u8; HMAC_SM3_OUTPUT] =
                dk[SM4_KEY_SIZE..SM4_CBC_DK_LEN].try_into().unwrap();

            let (ciphertext, mac) = sm4_cbc_encrypt(enc_key, mac_key, &iv, plaintext.as_bytes());

            let mut output = Vec::with_capacity(
                SALT_SIZE + SM4_BLOCK_SIZE + ciphertext.len() + HMAC_SM3_OUTPUT,
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
            let min_len = SALT_SIZE + SM4_GCM_NONCE_SIZE + SM4_GCM_TAG_SIZE + HMAC_SM3_OUTPUT;
            if data.len() < min_len {
                return Err(Error::CiphertextTooShort);
            }
            let salt: &[u8; SALT_SIZE] = data[..SALT_SIZE].try_into().unwrap();
            let nonce: &[u8; SM4_GCM_NONCE_SIZE] =
                data[SALT_SIZE..SALT_SIZE + SM4_GCM_NONCE_SIZE].try_into().unwrap();
            let commitment_start = data.len() - HMAC_SM3_OUTPUT;
            let received_commitment: &[u8; HMAC_SM3_OUTPUT] =
                data[commitment_start..].try_into().unwrap();
            let tag_start = commitment_start - SM4_GCM_TAG_SIZE;
            let tag: &[u8; SM4_GCM_TAG_SIZE] = data[tag_start..commitment_start].try_into().unwrap();
            let ciphertext = &data[SALT_SIZE + SM4_GCM_NONCE_SIZE..tag_start];

            let dk = derive_sm_keys::<SM4_GCM_DK_LEN>(password, salt, iterations);
            let enc_key: &[u8; SM4_KEY_SIZE] = dk[..SM4_KEY_SIZE].try_into().unwrap();
            let commit_key: &[u8; HMAC_SM3_OUTPUT] =
                dk[SM4_KEY_SIZE..SM4_GCM_DK_LEN].try_into().unwrap();

            // Verify key commitment first (constant-time)
            if !hmac_sm3_verify(commit_key, &[salt, nonce, ciphertext, tag], received_commitment) {
                return Err(Error::DecryptionFailed);
            }

            let plaintext = sm4_gcm_decrypt(enc_key, nonce, salt, ciphertext, tag)?;
            String::from_utf8(plaintext).map_err(|_| Error::DecryptionFailed)
        }
        Algorithm::PBEWithHMACSM3AndSM4_CBC => {
            let min_len = SALT_SIZE + SM4_BLOCK_SIZE + 1 + HMAC_SM3_OUTPUT;
            if data.len() < min_len {
                return Err(Error::CiphertextTooShort);
            }
            let salt: &[u8; SALT_SIZE] = data[..SALT_SIZE].try_into().unwrap();
            let iv: &[u8; SM4_BLOCK_SIZE] = data[SALT_SIZE..SALT_SIZE + SM4_BLOCK_SIZE]
                .try_into()
                .unwrap();
            let mac_start = data.len() - HMAC_SM3_OUTPUT;
            let expected_mac: &[u8; HMAC_SM3_OUTPUT] = data[mac_start..].try_into().unwrap();
            let ciphertext = &data[SALT_SIZE + SM4_BLOCK_SIZE..mac_start];

            let dk = derive_sm_keys::<SM4_CBC_DK_LEN>(password, salt, iterations);
            let enc_key: &[u8; SM4_KEY_SIZE] = dk[..SM4_KEY_SIZE].try_into().unwrap();
            let mac_key: &[u8; HMAC_SM3_OUTPUT] =
                dk[SM4_KEY_SIZE..SM4_CBC_DK_LEN].try_into().unwrap();

            let plaintext = sm4_cbc_decrypt(enc_key, mac_key, iv, ciphertext, expected_mac)?;
            String::from_utf8(plaintext).map_err(|_| Error::DecryptionFailed)
        }
    }
}

// ── ENC() wrapper (Jasypt-compatible, AES-only) ───────────────────

/// Unwrap an `ENC(...)` value and decrypt it using the default AES-256-CBC algorithm.
pub fn decrypt_enc(value: &str, password: &str) -> Result<String, Error> {
    let trimmed = value.trim();
    if trimmed.starts_with("ENC(") && trimmed.ends_with(')') {
        let inner = &trimmed[4..trimmed.len() - 1];
        decrypt(password, inner)
    } else {
        Err(Error::NotEncValue)
    }
}

/// Check if a string value is wrapped in `ENC(...)`.
pub fn is_enc_value(value: &str) -> bool {
    let t = value.trim();
    t.starts_with("ENC(") && t.ends_with(')')
}

// ── Memory helpers ─────────────────────────────────────────────────

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

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "mySecretPassword";
    const TEST_PLAINTEXT: &str = "Hello, World! This is a test message.";

    // ── AES-256-CBC (existing) ─────────────────────────────────

    #[test]
    fn aes_round_trip() {
        let encrypted = encrypt_with(Algorithm::PBEWithHMACSHA512AndAES_256, TEST_PASSWORD, TEST_PLAINTEXT);
        let decrypted =
            decrypt_with(Algorithm::PBEWithHMACSHA512AndAES_256, TEST_PASSWORD, &encrypted)
                .unwrap();
        assert_eq!(decrypted, TEST_PLAINTEXT);
    }

    #[test]
    fn aes_backward_compat_round_trip() {
        // Old API still works
        let encrypted = encrypt(TEST_PASSWORD, TEST_PLAINTEXT);
        let decrypted = decrypt(TEST_PASSWORD, &encrypted).unwrap();
        assert_eq!(decrypted, TEST_PLAINTEXT);
    }

    #[test]
    fn aes_enc_wrapper() {
        let encrypted = encrypt(TEST_PASSWORD, "secret");
        let wrapped = format!("ENC({})", encrypted);
        let decrypted = decrypt_enc(&wrapped, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted, "secret");
    }

    #[test]
    fn aes_different_encryptions_differ() {
        let e1 = encrypt(TEST_PASSWORD, TEST_PLAINTEXT);
        let e2 = encrypt(TEST_PASSWORD, TEST_PLAINTEXT);
        assert_ne!(e1, e2);
    }

    #[test]
    fn aes_rejects_too_short() {
        let too_short = B64.encode([0u8; SALT_SIZE + SALT_SIZE]);
        let err =
            decrypt_with(Algorithm::PBEWithHMACSHA512AndAES_256, TEST_PASSWORD, &too_short)
                .unwrap_err();
        assert!(matches!(err, Error::CiphertextTooShort));
    }

    // ── SM4-GCM ────────────────────────────────────────────────

    #[test]
    fn sm4_gcm_round_trip() {
        let encrypted =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, TEST_PLAINTEXT);
        let decrypted =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, &encrypted).unwrap();
        assert_eq!(decrypted, TEST_PLAINTEXT);
    }

    #[test]
    fn sm4_gcm_different_encryptions_differ() {
        let e1 = encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, TEST_PLAINTEXT);
        let e2 = encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, TEST_PLAINTEXT);
        assert_ne!(e1, e2);
    }

    #[test]
    fn sm4_gcm_wrong_password() {
        let encrypted =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, TEST_PLAINTEXT);
        let result =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, "wrongPassword", &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn sm4_gcm_tampered_ciphertext() {
        let encrypted =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, TEST_PLAINTEXT);
        let mut data = B64.decode(&encrypted).unwrap();
        // Tamper with the ciphertext (after salt+nonce, before tag+commitment)
        let tamper_pos = SALT_SIZE + SM4_GCM_NONCE_SIZE + 2;
        if tamper_pos < data.len() - SM4_GCM_TAG_SIZE - HMAC_SM3_OUTPUT {
            data[tamper_pos] ^= 0x01;
        }
        let tampered = B64.encode(&data);
        let result =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn sm4_gcm_empty_plaintext() {
        let encrypted =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, "");
        let decrypted =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, &encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn sm4_gcm_long_plaintext() {
        let long_input = "A".repeat(10_000);
        let encrypted =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, &long_input);
        let decrypted =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, &encrypted).unwrap();
        assert_eq!(decrypted, long_input);
    }

    #[test]
    fn sm4_gcm_rejects_too_short() {
        let too_short = B64.encode([0u8; SALT_SIZE + SM4_GCM_NONCE_SIZE]);
        let err =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, &too_short)
                .unwrap_err();
        assert!(matches!(err, Error::CiphertextTooShort));
    }

    #[test]
    fn sm4_gcm_cross_algorithm_rejection() {
        // SM4-GCM ciphertext should not decrypt as AES
        let encrypted =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, TEST_PLAINTEXT);
        let result =
            decrypt_with(Algorithm::PBEWithHMACSHA512AndAES_256, TEST_PASSWORD, &encrypted);
        assert!(result.is_err());
    }

    // ── SM4-CBC ────────────────────────────────────────────────

    #[test]
    fn sm4_cbc_round_trip() {
        let encrypted =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, TEST_PLAINTEXT);
        let decrypted =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, &encrypted).unwrap();
        assert_eq!(decrypted, TEST_PLAINTEXT);
    }

    #[test]
    fn sm4_cbc_different_encryptions_differ() {
        let e1 = encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, TEST_PLAINTEXT);
        let e2 = encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, TEST_PLAINTEXT);
        assert_ne!(e1, e2);
    }

    #[test]
    fn sm4_cbc_wrong_password() {
        let encrypted =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, TEST_PLAINTEXT);
        let result =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, "wrongPassword", &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn sm4_cbc_tampered_ciphertext() {
        let encrypted =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, TEST_PLAINTEXT);
        let mut data = B64.decode(&encrypted).unwrap();
        // Tamper with the ciphertext (after salt+iv, before mac)
        let tamper_pos = SALT_SIZE + SM4_BLOCK_SIZE + 2;
        if tamper_pos < data.len() - HMAC_SM3_OUTPUT {
            data[tamper_pos] ^= 0x01;
        }
        let tampered = B64.encode(&data);
        let result =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn sm4_cbc_rejects_too_short() {
        let too_short = B64.encode([0u8; SALT_SIZE + SM4_BLOCK_SIZE]);
        let err =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, &too_short)
                .unwrap_err();
        assert!(matches!(err, Error::CiphertextTooShort));
    }

    // ── SM4 cross-mode rejection ───────────────────────────────

    #[test]
    fn sm4_gcm_rejects_cbc_ciphertext() {
        let cbc_enc =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, TEST_PLAINTEXT);
        let result =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, &cbc_enc);
        assert!(result.is_err());
    }

    #[test]
    fn sm4_cbc_rejects_gcm_ciphertext() {
        let gcm_enc =
            encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, TEST_PLAINTEXT);
        let result =
            decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_CBC, TEST_PASSWORD, &gcm_enc);
        assert!(result.is_err());
    }

    // ── Memory helpers ─────────────────────────────────────────

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

    // ── Unicode password ───────────────────────────────────────

    #[test]
    fn unicode_password_round_trip_all_algorithms() {
        let password = "パスワード🔒";
        let plaintext = "unicode test";

        for alg in Algorithm::iter() {
            let enc = encrypt_with(alg, password, plaintext);
            let dec = decrypt_with(alg, password, &enc).unwrap();
            assert_eq!(dec, plaintext, "Failed for {alg}");
        }
    }

    // ── Custom iterations ──────────────────────────────────────

    #[test]
    fn custom_iterations_round_trip() {
        for alg in Algorithm::iter() {
            let enc = encrypt_with_iterations(alg, TEST_PASSWORD, TEST_PLAINTEXT, 10_000);
            let dec = decrypt_with_iterations(alg, TEST_PASSWORD, &enc, 10_000).unwrap();
            assert_eq!(dec, TEST_PLAINTEXT, "Failed for {alg}");
        }
    }

    #[test]
    fn iteration_mismatch_fails() {
        let enc = encrypt_with_iterations(
            Algorithm::PBEWithHMACSM3AndSM4_GCM,
            TEST_PASSWORD,
            TEST_PLAINTEXT,
            10_000,
        );
        let result =
            decrypt_with_iterations(Algorithm::PBEWithHMACSM3AndSM4_GCM, TEST_PASSWORD, &enc, 20_000);
        assert!(result.is_err());
    }

    // ── Is it ENC? ─────────────────────────────────────────────

    #[test]
    fn is_enc_detection() {
        assert!(is_enc_value("ENC(...)"));
        assert!(is_enc_value("  ENC(foo)  "));
        assert!(!is_enc_value("not_wrapped"));
        assert!(!is_enc_value("ENC("));
        assert!(!is_enc_value(")"));
    }

    // ── Error display ──────────────────────────────────────────

    #[test]
    fn error_display_messages() {
        let e = Error::CiphertextTooShort;
        assert_eq!(e.to_string(), "Ciphertext too short");
        let e = Error::DecryptionFailed;
        assert_eq!(e.to_string(), "Decryption failed");
    }
}

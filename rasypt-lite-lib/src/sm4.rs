//! SM4 cipher modes and HMAC-SM3 authentication helpers.

use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use ghash::{universal_hash::UniversalHash, GHash};
use hmac::{Hmac, Mac};
use sm3::Sm3;
use sm4::cipher::BlockCipherEncrypt;
use sm4::Sm4;
use subtle::ConstantTimeEq;

use crate::constants::{
    HMAC_SM3_OUTPUT_SIZE, SM4_BLOCK_SIZE, SM4_GCM_NONCE_SIZE, SM4_GCM_TAG_SIZE, SM4_KEY_SIZE,
};
use crate::Error;

type Sm4CbcEnc = cbc::Encryptor<Sm4>;
type Sm4CbcDec = cbc::Decryptor<Sm4>;

// ── HMAC-SM3 ──────────────────────────────────────────────────────

pub(crate) fn hmac_sm3_sign(key: &[u8], data: &[&[u8]]) -> [u8; HMAC_SM3_OUTPUT_SIZE] {
    let mut mac = <Hmac<Sm3>>::new_from_slice(key).expect("HMAC key size; Sm3 key is flexible");
    for chunk in data {
        mac.update(chunk);
    }
    mac.finalize().into_bytes().into()
}

pub(crate) fn hmac_sm3_verify(
    key: &[u8],
    data: &[&[u8]],
    expected: &[u8; HMAC_SM3_OUTPUT_SIZE],
) -> bool {
    let computed = hmac_sm3_sign(key, data);
    expected.ct_eq(&computed).into()
}

// ── SM4-GCM (using the ghash crate for authentication) ───────────

/// Increment the last 32 bits of a 16-byte block (big-endian).
fn inc_32(block: &mut [u8; 16]) {
    let val = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    let incremented = val.wrapping_add(1);
    block[12..16].copy_from_slice(&incremented.to_be_bytes());
}

/// Feed arbitrary byte data into a GHash instance, zero-padding to block boundaries.
fn ghash_update(ghash: &mut GHash, data: &[u8]) {
    let padded_len = data.len().div_ceil(SM4_BLOCK_SIZE) * SM4_BLOCK_SIZE;
    let mut padded = vec![0u8; padded_len];
    padded[..data.len()].copy_from_slice(data);
    let blocks: Vec<ghash::Block> = padded
        .chunks_exact(SM4_BLOCK_SIZE)
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
    let n = data.len().div_ceil(SM4_BLOCK_SIZE);
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

/// Precomputed SM4-GCM key stream parameters derived from the cipher key and nonce.
struct GcmParams {
    cipher: Sm4,
    h: [u8; SM4_BLOCK_SIZE],
    enc_j0: [u8; SM4_BLOCK_SIZE],
    icb: [u8; SM4_BLOCK_SIZE],
}

impl GcmParams {
    fn new(key: &[u8; SM4_KEY_SIZE], nonce: &[u8; SM4_GCM_NONCE_SIZE]) -> Self {
        let cipher = Sm4::new(&(*key).into());

        // H = E_K(0^128)
        let mut h_block: sm4::cipher::Block<Sm4> = [0u8; SM4_BLOCK_SIZE].into();
        cipher.encrypt_block(&mut h_block);
        let h: [u8; 16] = *h_block.as_ref();

        // J0 = nonce || 0^31 || 1
        let mut j0 = [0u8; SM4_BLOCK_SIZE];
        j0[..SM4_GCM_NONCE_SIZE].copy_from_slice(nonce);
        j0[15] = 1;

        // Encrypt J0 for the final tag XOR
        let mut enc_j0_block: sm4::cipher::Block<Sm4> = j0.into();
        cipher.encrypt_block(&mut enc_j0_block);
        let enc_j0: [u8; 16] = *enc_j0_block.as_ref();

        // GCTR starts at inc_32(J0)
        let mut icb = j0;
        inc_32(&mut icb);

        GcmParams {
            cipher,
            h,
            enc_j0,
            icb,
        }
    }

    fn compute_tag(&self, aad: &[u8], ciphertext: &[u8]) -> [u8; SM4_GCM_TAG_SIZE] {
        let s = compute_ghash(&self.h, aad, ciphertext);
        let mut tag = [0u8; SM4_GCM_TAG_SIZE];
        for i in 0..SM4_GCM_TAG_SIZE {
            tag[i] = s[i] ^ self.enc_j0[i];
        }
        tag
    }
}

pub(crate) fn sm4_gcm_encrypt(
    key: &[u8; SM4_KEY_SIZE],
    nonce: &[u8; SM4_GCM_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; SM4_GCM_TAG_SIZE]) {
    let params = GcmParams::new(key, nonce);
    let ciphertext = gctr(&params.cipher, params.icb, plaintext);
    let tag = params.compute_tag(aad, &ciphertext);
    (ciphertext, tag)
}

pub(crate) fn sm4_gcm_decrypt(
    key: &[u8; SM4_KEY_SIZE],
    nonce: &[u8; SM4_GCM_NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; SM4_GCM_TAG_SIZE],
) -> Result<Vec<u8>, Error> {
    let params = GcmParams::new(key, nonce);

    // Verify tag first (constant-time)
    let expected_tag = params.compute_tag(aad, ciphertext);
    if bool::from(expected_tag.ct_ne(tag)) {
        return Err(Error::DecryptionFailed);
    }

    Ok(gctr(&params.cipher, params.icb, ciphertext))
}

// ── SM4-CBC + Encrypt-then-HMAC-SM3 ───────────────────────────────

pub(crate) fn sm4_cbc_encrypt(
    key: &[u8; SM4_KEY_SIZE],
    mac_key: &[u8; HMAC_SM3_OUTPUT_SIZE],
    iv: &[u8; SM4_BLOCK_SIZE],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; HMAC_SM3_OUTPUT_SIZE]) {
    let encryptor = Sm4CbcEnc::new_from_slices(key, iv).unwrap();
    let ciphertext = encryptor.encrypt_padded_vec::<Pkcs7>(plaintext);

    // MAC = HMAC-SM3(mac_key, IV || ciphertext)
    let mac = hmac_sm3_sign(mac_key, &[iv, &ciphertext]);
    (ciphertext, mac)
}

pub(crate) fn sm4_cbc_decrypt(
    key: &[u8; SM4_KEY_SIZE],
    mac_key: &[u8; HMAC_SM3_OUTPUT_SIZE],
    iv: &[u8; SM4_BLOCK_SIZE],
    ciphertext: &[u8],
    expected_mac: &[u8; HMAC_SM3_OUTPUT_SIZE],
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

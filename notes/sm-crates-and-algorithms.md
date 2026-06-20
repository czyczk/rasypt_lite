# SM3/SM4 Crates and Algorithm Recommendations

## 1. Available Rust Crates

### SM3 (Hash)

| Crate | Version | Ecosystem | HMAC | HKDF | Notes |
|-------|---------|-----------|------|------|-------|
| **`sm3`** (RustCrypto) | 0.5.x | `digest` trait, `hmac`, `pbkdf2` crates | Via `hmac` crate | Via `hkdf` crate | Pure Rust, `no_std`, zeroize. Part of RustCrypto/hashes. |
| `gm-sm3` | 0.10.0 | None | No | No | Simple `sm3_hash()` only. No streaming. |
| `libsm` | 0.6.1 | Own `Sm3Hash` | No | No | Combined SM2/3/4. Most established combined crate. |
| **`libsmx`** | 0.3.0 | Own `Sm3Hasher` | Yes (`hmac_sm3`) | Yes | All-in-one SM2/3/4/9. Constant-time, `forbid(unsafe_code)`, bitsliced S-box. |

### SM4 (Block Cipher)

| Crate | Modes | Key | Ecosystem | Notes |
|-------|-------|-----|-----------|-------|
| **`sm4`** (RustCrypto) | Raw block (`cipher` trait) + `cbc`, `ctr`, `ofb`, `cfb` | 128-bit | RustCrypto | Raw primitive. Use with mode crates. |
| `sm4-gcm` | GCM only | 128-bit | Standalone | Thin wrapper. Last release Jan 2024. Effectively unmaintained. |
| **`libsmx`** | ECB, CBC, OFB, CFB, CTR, GCM, CCM, XTS | 128-bit | Own API | All modes built-in. Constant-time. Actively maintained. |
| `libsm` | ECB only | 128-bit | Own API | ECB only. No CBC/GCM. |
| `gm-rs` | ECB only | 128-bit | Own API | Limited. |

## 2. GM/T Standards

| Standard | Year | Content |
|----------|------|---------|
| GM/T 0002-2012 | 2012 | SM4 Block Cipher (replaced SMS4) |
| GM/T 0004-2012 | 2012 | SM3 Cryptographic Hash |
| GB/T 32905-2016 | 2016 | SM3 national standard update |
| GB/T 32907-2016 | 2016 | SM4 national standard update |
| **GM/T 0091-2020** | 2020 | **PBKDF + PBES + PBMAC** (password-based key derivation) |

### GM/T 0091-2020 — The PBE Standard

- **PBKDF**: PBKDF2 with PRF=HMAC-SM3
- **PBES**: SM4-CBC with PKCS#7 padding
- **PBMAC**: HMAC-SM3
- **Iterations**: >= 10,000 (general); >= 10,000,000 (high security)
- **Salt**: >= 8 bytes (16 recommended)
- **Derived key**: 128-bit for SM4

```
PBKDF2(HMAC-SM3, password, salt, iterations, dkLen=16)  → SM4 key
PBES = SM4-CBC(PKCS#7, key, IV)
```

## 3. SM4 Details

- **Key size**: Fixed 128-bit
- **Block size**: 16 bytes
- **SM3 digest**: 32 bytes (256-bit)
- **S-box**: Affine-isomorphic to AES S-box. Same differential uniformity (4) and algebraic degree (7) as AES. Standardized in ISO/IEC 18033-3:2010/Amd 1:2021.
- **Known attacks**: Best linear attack reaches 22/32 rounds (2^117). No practical attack on full 32 rounds.
- **Weak keys**: No known weak-key class in standard SM4.
- **Post-quantum**: 128-bit key → 64-bit quantum security (Grover). Not post-quantum resistant.

## 4. SM2 and Other SM Algorithms

- **SM2**: Asymmetric ECC. Not relevant for PBE directly. Used in key exchange at higher level.
- **SM1, SM7**: Not publicly disclosed. No open Rust implementations possible.
- **SM9**: Identity-based cryptography. `libsmx` supports it.
- **ZUC** (GM/T 0001): Stream cipher. Not relevant to PBE.

## 5. Recommended Crypto Scheme: PBEWithHMACSM3AndSM4

```
1. Key Derivation:
   dk = PBKDF2(PRF=HMAC-SM3, P=password, S=salt, c=iterations, dkLen=48)

2. Key Split (48 bytes):
   encryption_key = dk[0..16]       (128-bit SM4 key)
   auth_key       = dk[16..48]      (32-byte HMAC-SM3 key for authentication)

3. For GCM:
   ciphertext, tag = SM4-GCM(encryption_key, 12-byte-random-nonce, aad=salt, plaintext)
   key_commitment = HMAC-SM3(auth_key, salt || nonce || ciphertext || tag)
   Output: salt(16) || nonce(12) || ciphertext || tag(16) || commitment(32)

4. For CBC + Encrypt-then-HMAC:
   padded = PKCS#7(plaintext)
   ciphertext = SM4-CBC(encryption_key, 16-byte-random-IV, padded)
   mac = HMAC-SM3(auth_key, IV || ciphertext)
   Output: salt(16) || IV(16) || ciphertext || mac(32)
```

Note: Both modes use dkLen=48, not 80. The original 80-byte design reserved
extra key material for a separate CBC commit key, but Encrypt-then-MAC already
provides integrity for CBC — an additional commitment is unnecessary overhead.

## 6. Crate Recommendation

**Chosen: `sm3` 0.5 + `sm4` 0.6 + `ghash` 0.6 from RustCrypto.**

The `libsmx` crate (recommended in the original draft) has architectural
merits (bitsliced S-box, `forbid(unsafe_code)`) but does not implement the
RustCrypto `Digest` / `BlockCipher` traits. This means:

- PBKDF2-HMAC-SM3 would need a manual implementation instead of using the
  existing `pbkdf2` crate (which is generic over `Digest`).
- CBC mode would need a manual implementation instead of using the existing
  `cbc` crate (which is generic over `BlockCipher`).

With the RustCrypto ecosystem, `sm3` plugs into `pbkdf2` + `hmac` directly and
`sm4` plugs into `cbc` directly — zero new primitive code. For GCM, the proven
`ghash` crate (same crate backing `aes-gcm`) handles authentication; only the
GCTR (CTR-mode encryption) loop is written manually (~30 lines, trivially
verifiable).

**What about `sm4-gcm`?** The `sm4-gcm` crate was last released Jan 2024 and is
effectively unmaintained. It's unnecessary anyway — composing GCM from `sm4`
(raw block cipher) + `ghash` (authentication) + a thin GCTR loop is simpler
and uses well-maintained building blocks.

**API reference (what we actually use):**
```rust
use sm3::Sm3;
use sm4::Sm4;
use sm4::cipher::{KeyInit, BlockCipherEncrypt, Block};
use ghash::{GHash, universal_hash::UniversalHash};
use pbkdf2::pbkdf2_hmac;
use cbc::{Encryptor, Decryptor};

// PBKDF2 with SM3
pbkdf2_hmac::<Sm3>(password, salt, iterations, &mut dk);

// SM4-CBC (via cbc crate, same API as AES-256-CBC)
let enc = Encryptor::<Sm4>::new_from_slices(&key, &iv).unwrap();
let ct = enc.encrypt_padded_vec::<Pkcs7>(plaintext);

// SM4-GCM: GHASH via ghash crate, GCTR via manual SM4 block encryption
let mut ghash = GHash::new(&ghash::Key::from(h));
// ... feed AAD, ciphertext, length block
let s: [u8; 16] = ghash.finalize().into();
```

## 7. Alternatives (not chosen)

### `libsmx` 0.3

Architecturally impressive (bitsliced S-box, `forbid(unsafe_code)`, constant-time
throughout) but doesn't implement RustCrypto traits (`Digest`, `BlockCipher`).
Using it would require rewriting PBKDF2, CBC, and HMAC from scratch — all of
which already exist as well-tested generics in the RustCrypto ecosystem. Not
worth the duplication.

### `sm4-gcm`

Thin GCM wrapper around `sm4`. Last release Jan 2024, effectively unmaintained.
The `ghash` crate from RustCrypto provides the same functionality (GHASH) with
active maintenance and cross-validation against the `aes-gcm` crate.

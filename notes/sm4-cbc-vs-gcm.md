# SM4-CBC vs SM4-GCM for Password-Based Encryption

## 1. Cryptographic Properties

| Aspect | CBC | GCM |
|--------|-----|-----|
| Security goal | Confidentiality only | AEAD (confidentiality + integrity + authenticity) |
| Padding | PKCS#7 required | Not needed (stream mode) |
| Parallelization | Decrypt parallel, encrypt sequential | Both parallelizable |
| IV/nonce | 16 bytes, MUST be unpredictable (random) | 12 bytes, MUST be unique |

## 2. Attack Vectors

### CBC
- **Padding oracle attacks** (Vaudenay 2002): Still relevant. Any system reporting padding errors differently from MAC errors is vulnerable. Real-world: BEAST, POODLE, Lucky13.
- **CBC bit-flipping**: Without MAC, attacker flips bits in one block to corrupt next block.
- **IV manipulation**: Predictable IV enables chosen-plaintext attacks (BEAST).

### GCM
- **Nonce reuse**: Catastrophic. Single (key, nonce) reuse → recovers GHASH auth key → arbitrary forgery. Real-world: 184 HTTPS servers in 2016.
- **Key commitment / Partitioning oracle** (Len et al., USENIX '21): GCM is not key-committing. Single ciphertext decrypts under multiple keys. Enables password recovery attacks against PBE.
- **Short tags**: Forgery probability = (1 + n × ceil(L_A/128+1)) / 2^t. Tags <96 bits are dangerous.
- **Message length**: ~64 GiB per (key, nonce) pair (RFC 8998). Beyond this, security degrades.

## 3. Standards Alignment

| Standard | Mode | Context |
|----------|------|---------|
| GM/T 0091-2020 | SM4-CBC + PKCS#7 | PBES (Password-Based Encryption Scheme) |
| RFC 8998 | SM4-GCM | TLS 1.3 ShangMi cipher suites |
| GB/T 32907-2016 | SM4 core | Block cipher definition |

**GM/T 0091-2020 does not mention GCM** for PBE. SM4-CBC is the "standard instance."
**GCM is not prohibited** — GM/T 0091 uses a PBES2 framework that allows other ciphers.

## 4. PBE-Specific Considerations

### Fresh Key Per Message Changes the Risk Profile

With PBE, each encryption gets a fresh salt → fresh derived key. This means:
- **GCM nonce reuse is impossible** (new key each time, random nonce). The catastrophic scenario cannot arise.
- **Padding oracles** can only recover individual messages, not the password, but still dangerous.
- **Partitioning oracle** attacks still apply to GCM: attacker can craft multi-key-collision ciphertexts.

### Defense: Key Commitment

Add HMAC-SM3 commitment over (metadata || ciphertext || tag) using a separate derived key:
```
commitment = HMAC-SM3(commit_key, header || nonce || ciphertext || tag)
```
Verify this BEFORE attempting GCM decryption. On mismatch → single generic error.

## 5. CBC Implementation Requirements

### Correct Order: Encrypt-then-MAC

```
Encrypt:
  1. plaintext → PKCS#7 pad → padded
  2. Generate random 16-byte IV
  3. ciphertext = SM4-CBC(enc_key, IV, padded)
  4. mac = HMAC-SM3(mac_key, IV || ciphertext)
  5. Output: salt || IV || ciphertext || mac

Decrypt:
  1. Extract salt, derive keys
  2. Compute expected_mac = HMAC-SM3(mac_key, IV || ciphertext)
  3. Compare constant-time → REJECT if mismatch
  4. plaintext = SM4-CBC decrypt + unpad (via `decrypt_padded_vec::<Pkcs7>`)
  5. Return plaintext

Note: `decrypt_padded_vec::<Pkcs7>` handles padding verification internally.
If implementing raw CBC without the padded-vec helper, a separate constant-time
PKCS#7 unpad is needed (see code example below). In our implementation, the
MAC verification in step 3 runs before any decryption, so even if the library's
internal padding check were not constant-time, the MAC gate prevents the oracle.
```

**DO NOT** use MAC-then-encrypt (enables Lucky13 timing attacks).
**DO** use separate keys for encryption and MAC. Derive from PBKDF2 with distinct blocks.

### Constant-Time Padding Verification

```rust
fn pkcs7_unpad(data: &[u8]) -> Result<usize, Error> {
    if data.is_empty() { return Err(...); }
    let last = data[data.len() - 1];
    let pad_len = last as usize;
    if pad_len == 0 || pad_len > BLOCK_SIZE || pad_len > data.len() {
        return Err(...);
    }
    // XOR-accumulate: no short-circuit
    let mut accum: u8 = 0;
    let start = data.len() - pad_len;
    for i in start..data.len() {
        accum |= data[i] ^ last;
    }
    if accum != 0 { return Err(...); }
    Ok(start)
}
```

**Never** use `==` for byte comparisons — Rust's `slice::eq` short-circuits on first difference. Use `subtle::ConstantTimeEq::ct_eq()` instead.

## 6. Rust Ecosystem Support

| Approach | CBC | GCM | Constant-Time | Chosen |
|----------|-----|-----|---------------|--------|
| `sm4` + `cbc` + `ghash` crates (RustCrypto) | Yes | Yes (via `ghash` + manual GCTR) | MAC/tag via `subtle` | **YES** |
| `libsmx` 0.3 | Yes | Yes | Yes (bitsliced S-box) | Rejected — no RustCrypto trait impls |
| `sm4` + `cbc` crates only (RustCrypto) | Yes | No | — | — |
| `sm4` + `sm4-gcm` crates | No | Yes | Not assessed | No — `sm4-gcm` unmaintained |

**The chosen path:** `sm4` (block cipher) + `cbc` (CBC mode) + `ghash`
(GHASH authentication) + a thin GCTR loop (~30 lines). The `ghash` crate is
the same crate backing `aes-gcm`; it's well-tested against NIST vectors. This
is simpler than it sounds — three trusted building blocks, one small loop.

The original draft recommended `libsmx` as the sole dependency because it was
believed no generic RustCrypto GCM existed. In practice, composing GCM from
`sm4` + `ghash` is straightforward and avoids rewriting PBKDF2/CBC/HMAC from
scratch (which `libsmx` would require due to lack of trait compatibility).

## 7. Recommendation

| Criteria | GCM | CBC |
|----------|-----|-----|
| Authentication | Built-in | Manual (error-prone) |
| Padding oracles | Immune | Protected if Encrypt-then-MAC done correctly |
| Nonce/IV reuse risk | Catastrophic, but impossible in PBE (fresh key) | Predictable IV weakens security |
| Implementation complexity | Lower | Higher (2 keys, MAC, padding, ordering) |
| Standards | RFC 8998 (TLS) | GM/T 0091-2020 (PBE) |
| Government certification | Less tested for PBE | Standard instance |

**Default to SM4-GCM.** Rationale:
1. AEAD eliminates padding oracle class entirely
2. Fresh key per PBE message eliminates GCM's primary weakness
3. Simpler code → fewer bugs → better security
4. Add key commitment (HMAC-SM3) to defend partitioning oracle

**Offer SM4-CBC as a compatibility option** for GM/T 0091-2020 interop and certification scenarios.

Suggested naming:
- `PBEWithHMACSM3AndSM4_GCM` (modern AEAD profile)
- `PBEWithHMACSM3AndSM4_CBC` (GM/T 0091 compliant profile)

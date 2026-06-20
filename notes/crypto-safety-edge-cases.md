# Crypto Safety Edge Cases for SM3+SM4 PBE Implementation

## 1. Key Commitment / Partitioning Oracle Attacks in GCM

**What it is:** GCM is **not key-committing**. A single ciphertext can authenticate successfully under many different keys. In PBE (where keys are password-derived, hence low-entropy), an attacker observing success/failure can:
1. Craft a multi-key-collision ciphertext
2. Submit it once, observe the result
3. Partition password space logarithmically → recover password in ~log₂(n) queries instead of brute force

**Defense:**
- Add HMAC-based key commitment: `HMAC-SM3(commit_key, header || nonce || ciphertext || tag)` using a separate derived key
- Verify commitment BEFORE any decryption
- Return a single generic error on any failure — never distinguish between "bad password", "tampered data", or "MAC mismatch"
- This applies to both GCM and CBC modes

## 2. Constant-Time Operations (MUST)

Operations that MUST be constant-time:
| Operation | Why | Risk if not |
|-----------|-----|-------------|
| Tag/MAC comparison | Timing difference leaks which bytes matched | Key recovery via adaptive attacks |
| PKCS#7 padding verification | Short-circuit leak | Padding oracle (Vaudenay 2002, Lucky13) |
| Header/magic validation | Can reveal valid format to attacker | Minor oracle |

**Rust `==` for `[u8]`/`Vec<u8>` is NOT constant-time** — `slice::eq` short-circuits on the first differing byte.

**Fix:** Use `subtle::ConstantTimeEq::ct_eq()`:
```rust
use subtle::ConstantTimeEq;
if expected_mac.ct_ne(received_mac).into() {
    return Err("Decryption failed");
}
```

For padding verification: XOR-accumulate all padding bytes, check final accumulator. Never short-circuit on mismatched byte.

## 3. PBKDF2 Safety

| Standard | Recommendation | Year |
|----------|---------------|------|
| OWASP Cheat Sheet | **600,000** iterations (HMAC-SHA256) | 2023+ |
| OWASP ASVS | 600,000 | 2023 |
| NIST SP 800-63B | 10,000 (obsolete minimum) | 2017 |
| NIST SP 800-132 | 1,000 (completely obsolete) | 2010 |

**For PBKDF2-HMAC-SM3:** SM3 has 256-bit output like SHA-256. Its compression
function is similar (Merkle-Damgård). SM3 has no hardware acceleration on x86,
making high iteration counts expensive in software. Our default of 10,000
matches the GM/T 0091-2020 general-use minimum. For production use, pass
`--iterations 600000` (220 ms in release builds, ~5 s in debug). See
`algorithm-comparison.md` for benchmarks.

**Parallelization resistance:** PBKDF2 has zero memory-hardness. Brute force parallelizes linearly across GPUs/FPGAs/ASICs. PBKDF2 is acceptable only with very high iteration count + strong password. For higher security, consider Argon2id or scrypt (not SM-standard, but cryptographically stronger).

**SM3 as HMAC PRF:** No known structural weaknesses affecting HMAC use. Published attacks: preimage against 30/64 steps (2^249), collisions against 20/64 steps (practical). None affect PBKDF2's security model.

## 4. Salt Generation

| Requirement | Value |
|-------------|-------|
| Minimum length | **16 bytes (128 bits)** per NIST SP 800-132 §5.1 |
| RNG | OS CSPRNG |
| Common mistake | Using 8 bytes (64-bit) — too short, enables precomputation attacks |

**Implementation note:** We use `rand::rng()` which on Linux seeds from
`getrandom` (i.e., `/dev/urandom`). Both `rand::thread_rng()` and direct
`getrandom` are CSPRNGs. The distinction matters more for embedded/no_std
contexts where `rand` may pull in extra dependencies. For a CLI tool on a
standard OS, either is fine. Our code uses `rand` primarily for consistency
with the existing AES path that already depended on it.

## 5. SM4-Specific Safety

- **Key size**: Fixed 128-bit. Provides 64-bit quantum security (Grover). Acceptable for classical computing.
- **No known weak keys** in standard SM4.
- **S-box**: Affine-isomorphic to AES S-box. No backdoor identified. Declassified and published as GB/T 32907-2016.
- **Side-channel**: SM4 is vulnerable to power analysis and fault injection with physical access. Software side-channel (cache timing) is mitigated by bitsliced S-box implementations (like `libsmx`).

## 6. GCM-Specific Safety

| Concern | Guidance |
|---------|----------|
| Maximum message size | ~64 GiB per (key, nonce) pair (RFC 8998). Practical for files. |
| Nonce format | 12 bytes (96-bit). Random generation safe for PBE due to fresh key per message. |
| Tag length | 16 bytes (128-bit). Do not truncate — high-value password-protected data. |
| AAD | Use it. Include version, algorithm ID, and salt to prevent downgrade attacks. |
| Nonce reuse | Catastrophic. Fresh key per PBE message makes this impossible if correctly implemented. |

## 7. Unicode Password Normalization

- **NFC normalization** is correct (RFC 8265, PRECIS framework "OpaqueString" profile)
- **No case mapping** (correct — passwords are case-sensitive)
- **Strip or reject zero-width characters**: U+200B, U+200C, U+200D, U+FEFF. These are invisible and can create passwords that look identical but aren't. *(Not yet implemented in our code — passwords are NFC-normalized but zero-width chars are not stripped.)*
- **Minimum password length**: Enforce >= 8 characters. Our CLI warns below 8 (suppressible with `--quiet`).
- RFC 8265 recommends against rejecting non-ASCII characters — accept full Unicode but normalize to NFC.

## 8. Memory Safety

- **`zeroize` crate**: Use `write_volatile` + `compiler_fence(SeqCst)`. LLVM MUST honor volatile writes — cannot optimize away zeroization. Ensure version >= 1.5.
- **`Vec<u8>` for keys**: `zeroize` zeros entire capacity, not just length. But reallocation may leave copies in old heap locations. Consider `secrecy::SecretVec` for stronger guarantees.
- **`Drop` impl**: Always implement `Drop` with `zeroize` on structs containing keys. If using custom derive, add manual `Drop`.
- **Never derive `Copy`** on types containing key material — prevents multiple copies existing simultaneously.

## 9. Format/Header Security

- **Put salt, IV/nonce inside authenticated envelope** (as AAD in GCM, or in MAC input for CBC)
- **Do not** authenticate only the ciphertext — unauthenticated headers enable downgrade attacks
- **What we implemented:**
  - GCM: AAD = salt (binds the ciphertext to its derivation parameters). Nonce and tag are covered by the HMAC-SM3 key commitment.
  - CBC: MAC covers `IV || ciphertext`. Salt is not in the MAC — an attacker could swap salts between two ciphertexts encrypted with the same password, causing decryption under the wrong derived key. In practice this only produces garbage output (MAC will fail under the wrong key), so it's a denial-of-service vector, not a confidentiality risk.
- **Constant-time magic byte verification** — use `subtle::ct_eq`, not `==`
- **Version byte**: Not yet implemented. A future format version could be added as a first byte with constant-time rejection of unknown versions.
- **Truncated input**: Return generic error. Never attempt partial decryption.

## 10. Error Handling — The "Cryptographic Doom Principle"

**All decryption failures must produce the same single generic error.** Never distinguish between:
- Wrong password
- Corrupted/tampered ciphertext
- Invalid MAC/tag
- Invalid padding
- Unsupported version
- Truncated input

Any observable difference (error message, timing, error code) is an oracle that enables attacks.

## 11. Summary Checklist

| Priority | Item | Recommendation | Status |
|----------|------|----------------|--------|
| CRITICAL | PBKDF2 iterations | >= 10,000 default (GM/T 0091 minimum); 600,000 via --iterations | Done |
| CRITICAL | Salt size | >= 16 bytes | Done |
| CRITICAL | Constant-time ops | `subtle` crate for all comparisons | Done |
| HIGH | Key commitment | HMAC-SM3 for GCM | Done |
| HIGH | Error messages | Single generic "decryption failed" | Done |
| HIGH | Encrypt-then-MAC | Verify MAC before decrypting (CBC) | Done |
| MEDIUM | Zero-width chars | Strip from passwords | Not yet |
| MEDIUM | Min password length | Enforce >= 8 characters | Done (CLI warning) |
| MEDIUM | AAD | Include salt, version, algorithm in AAD | Salt in AAD (GCM). Version/algorithm not yet. |
| LOW | SecretVec | Consider for key storage | Not yet |

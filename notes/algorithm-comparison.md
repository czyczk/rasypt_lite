# Algorithm Comparison

## At a glance

| | AES-256-CBC | SM4-GCM | SM4-CBC |
|---|---|---|---|
| **Confidentiality** | Yes | Yes | Yes |
| **Integrity / auth** | No | Yes (AEAD) | Yes (Encrypt-then-MAC) |
| **Tampering detected?** | No — silent corruption | Yes — tag fails | Yes — MAC fails |
| **Padding oracle risk** | Present | Immune | Mitigated (MAC first) |
| **Key commitment** | No | HMAC-SM3 | — |
| **Iterations (default)** | 1,000 | 10,000 | 10,000 |
| **Derivation time (release)** | <1 ms | ~4 ms | ~4 ms |
| **Derivation time (debug)** | ~7 ms | ~85 ms | ~85 ms |
| **Brute-force cost** | ~1 GPU-hour | ~10 GPU-hours | ~10 GPU-hours |
| **Quantum security** | 128-bit (Grover) | 64-bit | 64-bit |

The SM combos are safer than the AES variant by a wide margin. The AES variant exists for
Jasypt backward compatibility only.

---

## Why the SM combos are safer

### 1. Authentication — the biggest gap

**AES-256-CBC has no authentication.** An attacker who can modify the ciphertext
can flip bits in one block to corrupt the next block's plaintext, and the
decryptor will never know. There's no MAC, no tag, nothing. The output is
accepted as valid and any garbage bytes are returned as "plaintext."

**SM4-GCM is AEAD.** Every decryption verifies a 128-bit authentication tag
before returning a single byte. Tampered ciphertext → `DecryptionFailed`.
Always.

**SM4-CBC is Encrypt-then-MAC.** Before touching the ciphertext, the decryptor
computes `HMAC-SM3(key, IV || ciphertext)` and compares it constant-time
against the stored MAC. Mismatch → `DecryptionFailed`.

### 2. Padding oracles don't exist in GCM

CBC requires PKCS#7 padding. A naive CBC implementation that reports "bad
padding" differently from "wrong password" leaks a padding oracle (Vaudenay
2002). Our SM4-CBC mitigates this by verifying the MAC *first* and returning
the exact same error for every failure. But the safest fix is to not have
padding at all — which is what GCM does.

### 3. Key commitment defends partitioning oracles

GCM is not key-committing: a single ciphertext can authenticate under many
different keys. For password-derived keys (low entropy), this enables
partitioning oracle attacks (Len et al., USENIX '21) where an attacker submits
one crafted ciphertext and observes success/failure to binary-search the
password space.

Our defense: before GCM decryption, verify `HMAC-SM3(commit_key, salt ||
nonce || ciphertext || tag)` using a *separate* derived key. Only one key
produces a valid commitment → the partitioning attack collapses.

### 4. 10× more PBKDF2 iterations

The AES variant uses 1,000 iterations — the Jasypt default from 2014. SM4-GCM
and SM4-CBC use 10,000, matching the GM/T 0091-2020 "general use" minimum. At
1,000 iterations, a single GPU cracks ~10^9 passwords/day. At 10,000, the
same GPU cracks ~10^8/day — one order of magnitude slower.

Higher counts are available via `--iterations`. The default is chosen for CLI
responsiveness (see section below).

---

## GCM vs CBC — why both exist

### SM4-GCM (default for new encryption)

**The good:**
- AEAD in one operation. No separate MAC, no padding, no ordering mistakes.
- Both encrypt and decrypt are fully parallelizable.
- Immune to padding oracles by design.
- Widely adopted: RFC 8998 (TLS 1.3 ShangMi suites), GM/T 0022-2023 (IPSec).

**The catch:**
- Nonce reuse is catastrophic. Same `(key, nonce)` twice → recover the GHASH
  authentication key → arbitrary forgeries. In PBE, each encryption gets a
  fresh salt → fresh key → nonce reuse is impossible by construction.
- GCM is not key-committing. We add HMAC-SM3 commitment (see above).
- ~64 GiB message limit per `(key, nonce)` pair. Irrelevant for PBE.

### SM4-CBC (GM/T 0091-2020 compliance)

**The good:**
- GM/T 0091-2020 explicitly specifies SM4-CBC for PBES. If you need
  certification or interop with Chinese government systems, this is the
  standard instance.
- IV only needs to be unpredictable (random is fine).
- No message length limit.

**The catch:**
- Requires Encrypt-then-MAC (two keys, correct ordering, constant-time MAC
  verification before decryption). More code → more surface for bugs.
- PKCS#7 padding. Even with MAC-first, the padding code still runs if MAC
  passes (though MAC passing means the attacker already knows the MAC key, so
  the oracle is moot).
- Encryption is sequential (CBC chaining).

### Why not GCM-only

GM/T 0091-2020 does not define a GCM variant. For compliance certification,
CBC is the only option. For everyone else, GCM is simpler and safer.

---

## Why 10,000 iterations (and why not 600,000)

### The real numbers

PBKDF2-HMAC-SM3 benchmarked on an i7-12700H (release build):

| Iterations | Time (release) | Time (debug) |
|---|---|---|
| 1,000 | 0.4 ms | 6 ms |
| 10,000 | 3.7 ms | 85 ms |
| 100,000 | 34 ms | 820 ms |
| 600,000 | 220 ms | 4.9 s |

**The 9-second gap is debug vs release.** In debug mode, Rust skips inlining
and loop optimizations. SM3's compression function (64 rounds, 32-bit
operations, no hardware acceleration on x86) is sensitive to this — it runs
~20× slower without optimizations. A release build (`cargo build --release`
or `cargo install`) eliminates the gap.

### Why 10,000 as the default

1. **GM/T 0091-2020 minimum.** The standard says ≥ 10,000 for general use.
   This is the natural baseline for an SM-compliant tool.
2. **Fast in every build mode.** 3.7 ms in release, 85 ms in debug. Well within
   the 300 ms threshold for a responsive CLI.
3. **Use `--iterations` for more.** Anyone who wants OWASP-level 600,000 can
   pass `--iterations 600000`. It takes 220 ms in release — still perfectly
   usable. The default stays conservative for quick CLI interactions.

### Why not 600,000 as the default

- **Debug mode is painful.** 4.9 seconds per derivation. Developers doing
  `cargo run` (without `--release`) would hate it.
- **10,000 is already 10× better than AES.** The existing Jasypt-compatible
  default is 1,000. Moving the SM default to 10,000 is already a significant
  upgrade.
- **SM3 has no hardware acceleration on x86.** SHA-512 benefits from SHA-NI
  on modern Intel/AMD CPUs (~3-10× speedup). SM3 is pure software, making
  high iteration counts disproportionately expensive.
- **The user can always go higher.** `--iterations 600000` or even
  `--iterations 10000000` for archival encryption where a few seconds of wait
  is acceptable.

### What OWASP and NIST say

| Source | Year | Recommendation |
|---|---|---|
| OWASP Cheat Sheet | 2023 | 600,000 (HMAC-SHA256) |
| OWASP ASVS 4.0 | 2023 | 600,000 |
| NIST SP 800-63B | 2017 | 10,000 (minimum) |
| NIST SP 800-132 | 2010 | 1,000 (obsolete) |
| **GM/T 0091-2020** | 2020 | **≥ 10,000 (general)**, ≥ 10,000,000 (high-security) |

We follow GM/T 0091-2020's general-use recommendation. The OWASP 600,000
number is for SHA-256 on hardware with acceleration; applying it directly to
SM3 (pure software on x86) would make the CLI unusable in debug builds.
600,000 is available as an opt-in via `--iterations`.

### SM3 has no hardware acceleration on x86 — and that matters

SHA-512 at 600,000 iterations takes ~250 ms in release (SHA-NI accelerated)
but **9 seconds in debug** — same scale as SM3's debug penalty. The difference
is that SHA-512 has hardware acceleration, so its release build is 36× faster.
SM3 has no such acceleration; its release build is "only" 22× faster than
debug. Both algorithms suffer in debug mode, but SM3 gets less relief from the
compiler because its inner loop is register-heavy and resists auto-vectorization.

---

## Key sizes and security margins

| | AES-256 | SM4-128 |
|---|---|---|
| Key size | 256 bits | 128 bits |
| Classical security | 256 bits | 128 bits |
| Quantum security (Grover) | 128 bits | 64 bits |
| Best known attack | 7/14 rounds (biclique, 2^254) | 22/32 rounds (linear, 2^117) |
| Rounds (full) | 14 | 32 |
| Hardware acceleration | AES-NI (universal) | ARMv8.4-A SM4 (rare) |

AES-256 has a higher security margin on paper. SM4-128 is still well above
brute-force feasibility (2^128 classical, 2^64 quantum). No practical attack
on full-round SM4 exists. For the threat model of a password-based encryption
CLI tool — protecting data at rest with a human-chosen password — the password
entropy dominates. A 40-bit password with 256-bit AES is weaker than a 60-bit
password with 128-bit SM4.

---

## What the AES variant still does well

- **Interop**: It's the only algorithm compatible with Jasypt/Spring Boot
  `ENC(...)` values. If you're decrypting config files from a Java stack, you
  need it.
- **Speed**: 1,000 iterations means sub-millisecond derivation. Useful in
  hot paths where you're decrypting hundreds of values (though you shouldn't
  be doing that with PBKDF2).
- **AES-NI**: Hardware-accelerated on all modern x86 CPUs. SM4 is software-only
  on most platforms.

---

## Summary recommendation

| Use case | Algorithm |
|---|---|
| New encryption, general use | **SM4-GCM** |
| GM/T 0091-2020 compliance | SM4-CBC |
| Jasypt/Spring Boot interop | AES-256-CBC |
| Maximum brute-force resistance | SM4-GCM + `--iterations 600000` |

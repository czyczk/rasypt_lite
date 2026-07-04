# rasypt-lite

Password-based encryption library and CLI supporting multiple algorithms:

| Algorithm | Default | Cipher | Auth | Standard |
|---|---|---|---|---|
| `PBEWithHMACSHA512AndAES_256` | yes | AES-256-CBC | — | Jasypt 3.x |
| `PBEWithHMACSM3AndSM4_GCM` | — | SM4-GCM | AEAD + HMAC-SM3 key commit | GM/T 0091† |
| `PBEWithHMACSM3AndSM4_CBC` | — | SM4-CBC | Encrypt-then-HMAC-SM3 | GM/T 0091-2020 |

† GCM mode is a modern extension to the PBES2 framework.

Three crates in this workspace:

- **`rasypt-lite-lib`** — core library: `encrypt`, `decrypt`, `ENC(...)` helpers, secure memory zeroing.
- **`rasypt-lite-cli`** — CLI tool with `--algorithm` / `-a` and `--iterations`.
- **`rasypt-lite-derive`** — proc macro `#[derive(RasyptDecrypt)]` for struct field decryption.

---

## Basic library usage

```toml
[dependencies]
rasypt-lite-lib = "1"
```

```rust
use rasypt_lite_lib::{encrypt_with, decrypt_with, Algorithm};

let ciphertext = encrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, "password", "hello world");
let plaintext = decrypt_with(Algorithm::PBEWithHMACSM3AndSM4_GCM, "password", &ciphertext).unwrap();
assert_eq!(plaintext, "hello world");
```

The default algorithm is `PBEWithHMACSHA512AndAES_256` for backward compatibility:

```rust
use rasypt_lite_lib::{encrypt, decrypt};  // always uses AES-256-CBC

let ct = encrypt("pass", "plain");
let pt = decrypt("pass", &ct).unwrap();
```

### Algorithm defaults

| Algorithm | Iterations | Key size |
|---|---|---|
| `PBEWithHMACSHA512AndAES_256` | 1,000 | 256-bit |
| `PBEWithHMACSM3AndSM4_GCM` | 10,000 | 128-bit |
| `PBEWithHMACSM3AndSM4_CBC` | 10,000 | 128-bit |

Override iterations with `encrypt_with_iterations` / `decrypt_with_iterations`.

---

## CLI

```
rasypt-lite encrypt --input "secret" --password "mypass" --algorithm PBEWithHMACSM3AndSM4_GCM
rasypt-lite decrypt --input "base64..." --password "mypass" --algorithm PBEWithHMACSM3AndSM4_GCM
```

| Flag | Short | Description |
|---|---|---|
| `--input` | `-i` | Literal value to process |
| `--file`, `--path` | `-f` | Process a UTF-8 text file containing `DEC(...)` / `ENC(...)` markers |
| `--in-place` | — | Overwrite the source file instead of writing transformed content to stdout |
| `--algorithm` | `-a`, `--alg` | Algorithm name (default: `PBEWithHMACSHA512AndAES_256`) |
| `--iterations` | — | Override PBKDF2 iteration count |
| `--wrap` | — | Wrap literal AES output in `ENC(...)` |
| `--quiet` | `-q` | Silence password warnings |

Literal decrypt accepts both bare Base64 ciphertext and `ENC(...)`-wrapped
ciphertext for all supported algorithms. File mode rewrites only marked values:
`DEC(...)` becomes `ENC(...)` during encrypt, and `ENC(...)` becomes `DEC(...)`
during decrypt.

---

## Derive macro

```rust
use rasypt_lite_derive::RasyptDecrypt;

#[derive(RasyptDecrypt)]
struct Config {
    #[rasypt(encrypted)]
    secret: String,
}
```

The derive macro supports an optional `algorithm` parameter for SM algorithms.
See [`rasypt-lite-derive/README.md`](rasypt-lite-derive/README.md).

---

# Compatibility

- The default of `PBEWithHMACSHA512AndAES_256` is fully compatible with Jasypt.
- The SM-based alternatives provide better security but do not exist in Jasypt, so no Jasypt compatibility guaranteed. The default is sufficient for quick-launching apps.

---

## Security

- **SM4-GCM**: Authenticated encryption (AEAD) with 128-bit GCM tag. HMAC-SM3 key commitment defends against partitioning oracle attacks.
- **SM4-CBC**: Encrypt-then-MAC. MAC verified before decryption (constant-time). Separate encryption and MAC keys.
- **Constant-time**: All MAC/tag comparisons use the `subtle` crate. Single generic error for all decryption failures — no oracle leakage.
- **Key derivation**: PBKDF2 with 10,000 iterations default (SM algorithms, matches GM/T 0091-2020). Override with `--iterations` for higher counts (600,000 recommended for production). NFC-normalized passwords. Key material zeroized after use.
- **Salt**: 16 bytes (128-bit) from OS CSPRNG, fresh per encryption.

---

## License

MIT OR Apache-2.0

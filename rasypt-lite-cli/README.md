# rasypt-lite CLI

Command-line wrapper around `rasypt-lite-lib` for encrypting/decrypting
strings with password-based encryption.

## Installation

```
cargo install --path rasypt-lite-cli
```

Or `cargo build --release` from the workspace root; the binary is at
`target/release/rasypt-lite`.

## Usage

```
rasypt-lite <COMMAND>

Commands:
  encrypt    Encrypt a plaintext value
  decrypt    Decrypt an encrypted value
  help       Print this message or the help of the given subcommand(s)

Options:
  -q, --quiet  Silence non-fatal warnings
  -h, --help   Print help
```

### Encrypt

```
rasypt-lite encrypt --input <INPUT> --password <PASSWORD> [OPTIONS]
```

| Flag | Description |
|---|---|
| `-i`, `--input` | Plaintext to encrypt |
| `-p`, `--password` | Password for key derivation |
| `-a`, `--algorithm`, `--alg` | Algorithm (default: `PBEWithHMACSHA512AndAES_256`) |
| `--iterations` | Override PBKDF2 iteration count |
| `--wrap` | Wrap output in `ENC(...)` (AES only) |

Valid algorithms: `PBEWithHMACSHA512AndAES_256`, `PBEWithHMACSM3AndSM4_GCM`,
`PBEWithHMACSM3AndSM4_CBC`.

### Decrypt

```
rasypt-lite decrypt --input <INPUT> --password <PASSWORD> [OPTIONS]
```

Same flags as encrypt. The `--algorithm` and `--iterations` must match what was
used during encryption.

## Examples

```sh
# AES-256-CBC (default, Jasypt-compatible)
rasypt-lite encrypt -i "top secret" -p "mypassword"
rasypt-lite decrypt -i "base64output..." -p "mypassword"

# SM4-GCM (authenticated encryption)
rasypt-lite encrypt -i "hello" -p "mypass" -a PBEWithHMACSM3AndSM4_GCM
rasypt-lite decrypt -i "base64output..." -p "mypass" -a PBEWithHMACSM3AndSM4_GCM

# Custom iteration count
rasypt-lite encrypt -i "secret" -p "pass" -a PBEWithHMACSM3AndSM4_GCM --iterations 600000
rasypt-lite decrypt -i "base64output..." -p "pass" -a PBEWithHMACSM3AndSM4_GCM --iterations 600000

# ENC(...) wrapping (AES only, for Jasypt/Spring Boot interop)
rasypt-lite encrypt -i "secret" -p "mypass" --wrap
# Output: ENC(base64...)
```

## Password warnings

Passwords shorter than 8 characters produce a warning to stderr. Suppress with
`--quiet`.

## Performance

PBKDF2 iterations affect derivation time. Defaults:

| Algorithm | Iterations | Release | Debug |
|---|---|---|---|
| AES-256-CBC | 1,000 | <1 ms | ~7 ms |
| SM4-GCM | 10,000 | ~4 ms | ~85 ms |
| SM4-CBC | 10,000 | ~4 ms | ~85 ms |

Use `--release` for normal use (`cargo build --release` or `cargo install`).
Debug builds are ~20× slower due to missing compiler optimizations on the SM3
inner loop.

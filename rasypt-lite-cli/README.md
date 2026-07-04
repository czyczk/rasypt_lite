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
rasypt-lite encrypt (--input <INPUT> | --file <FILE>) --password <PASSWORD> [OPTIONS]
```

| Flag | Description |
|---|---|
| `-i`, `--input` | Literal plaintext to encrypt |
| `-f`, `--file`, `--path` | Process a UTF-8 text file instead of a literal input |
| `--in-place` | Overwrite the source file instead of writing transformed content to stdout |
| `-p`, `--password` | Password for key derivation |
| `-a`, `--algorithm`, `--alg` | Algorithm (default: `PBEWithHMACSHA512AndAES_256`) |
| `--iterations` | Override PBKDF2 iteration count |
| `--wrap` | Wrap literal AES output in `ENC(...)` |

Valid algorithms: `PBEWithHMACSHA512AndAES_256`, `PBEWithHMACSM3AndSM4_GCM`,
`PBEWithHMACSM3AndSM4_CBC`.

When `--file` is used, encrypt mode only rewrites `DEC(...)` markers to
`ENC(...)`; everything else is left unchanged.

### Decrypt

```
rasypt-lite decrypt (--input <INPUT> | --file <FILE>) --password <PASSWORD> [OPTIONS]
```

Same flags as encrypt except `--wrap`. Literal decrypt accepts both bare
Base64 ciphertext and `ENC(...)`-wrapped ciphertext for every supported
algorithm. The `--algorithm` and `--iterations` must match what was used during
encryption.

When `--file` is used, decrypt mode only rewrites `ENC(...)` markers to
`DEC(...)`; everything else is left unchanged.

CLI stdout does not append an extra trailing newline.

## Examples

```sh
# AES-256-CBC (default, Jasypt-compatible)
rasypt-lite encrypt -i "top secret" -p "mypassword"
rasypt-lite decrypt -i "base64output..." -p "mypassword"
rasypt-lite decrypt -i "ENC(base64output...)" -p "mypassword"

# SM4-GCM (authenticated encryption)
rasypt-lite encrypt -i "hello" -p "mypass" -a PBEWithHMACSM3AndSM4_GCM
rasypt-lite decrypt -i "base64output..." -p "mypass" -a PBEWithHMACSM3AndSM4_GCM
rasypt-lite decrypt -i "ENC(base64output...)" -p "mypass" -a PBEWithHMACSM3AndSM4_GCM

# Custom iteration count
rasypt-lite encrypt -i "secret" -p "pass" -a PBEWithHMACSM3AndSM4_GCM --iterations 600000
rasypt-lite decrypt -i "base64output..." -p "pass" -a PBEWithHMACSM3AndSM4_GCM --iterations 600000

# ENC(...) wrapping (AES only, for Jasypt/Spring Boot interop)
rasypt-lite encrypt -i "secret" -p "mypass" --wrap
# Output: ENC(base64...)

# File mode: only DEC(...) markers are encrypted
rasypt-lite encrypt -f ./application.yml -p "mypass" -a PBEWithHMACSM3AndSM4_GCM

# Overwrite the file in place
rasypt-lite decrypt -f ./application.yml -p "mypass" --in-place
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

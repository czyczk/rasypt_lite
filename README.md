# rasypt-lite

`rasypt-lite` is a small Rust implementation of the Jasypt
[PBEWithHMACSHA512AndAES_256](https://www.jasypt.org/) encryption scheme. It
consists of three crates in this workspace:

- **`rasypt-lite-lib`** – the core library providing `encrypt`, `decrypt`,
  helpers for handling `ENC(...)` wrappers and utilities for zeroizing
  sensitive `String` values.
- **`rasypt-lite-cli`** – a simple command‑line tool built on top of the
  library for encrypting/decrypting from the shell.
- **`rasypt-lite-derive`** – a procedural macro crate that can derive
  `RasyptDecrypt` for structs, adding methods that will decrypt
  `ENC(...)`‑wrapped `String`/`Option<String>` fields explicitly tagged with
  `#[rasypt(encrypted)]`, and optionally zero them on drop.

This README provides the minimal information needed to get started. See the
`README.md` files inside the `rasypt-lite-cli` and `rasypt-lite-derive` folders
for more detailed examples and CLI/derive‑specific documentation.

---

## Basic library usage

Add the library to your `Cargo.toml`:

```toml
[dependencies]
rasypt-lite-lib = "0.1"
```

Encrypt and decrypt strings with a password:

```rust
use rasypt_lite_lib::{encrypt, decrypt};

let passwd = "secret";
let plaintext = "hello world";

let ciphertext = encrypt(plaintext, passwd);
assert_ne!(ciphertext, plaintext);

let decrypted = decrypt(&ciphertext, passwd).expect("decryption failed");
assert_eq!(decrypted, plaintext);
```

You can also wrap values in `ENC(...)` manually or via helper functions, e.g.
`encrypt(plaintext, passwd)` returns the base64 blob that you can feed to
`decrypt_enc`.

## Command‑line tool (CLI)

The CLI can be used to encrypt/decrypt values from the shell. The simplest
usage is:

```sh
# encrypt a password
rasypt-lite encrypt --password mypass "super secret"

# decrypt
rasypt-lite decrypt --password mypass "ENC(abcd...)"
```

For more options (iteration count, reading from files, etc.) refer to the
[CLI README](rasypt-lite-cli/README.md).

## Derive macro

If you have a configuration struct or similar that contains encrypted values
wrapped with `ENC(...)`, you can automatically decrypt and clear them:

```rust
use rasypt_lite_derive::RasyptDecrypt;

#[derive(RasyptDecrypt)]
struct Config {
    username: String,
    #[rasypt(encrypted)]
    api_key: Option<String>,
    #[rasypt(encrypted)]
    secret: String,
}

let mut cfg = Config {
    username: "plain-user".into(),
    api_key: Some("ENC(...base64...)".into()),
    secret: "ENC(...)".into(),
};
cfg.decrypt_enc_fields("password")?;
// tagged values are now plaintext; untagged fields are unchanged
```

The derive crate also provides `clear_sensitive_fields()` and, by default, a
`Drop` impl that zeroizes the fields when the struct is dropped. See
[`rasypt-lite-derive/README.md`](rasypt-lite-derive/README.md) for the full
documentation and additional examples.

---

_Project maintained as part of a Rust workbook._

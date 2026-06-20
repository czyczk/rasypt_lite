# rasypt-lite-derive

Procedural macro `#[derive(RasyptDecrypt)]` for structs with encrypted fields.

When derived, the struct gains:

- `decrypt_enc_fields(&mut self, password: &str) -> Result<(), Error>` — walks
  fields tagged `#[rasypt(encrypted)]`, checks for `ENC(...)` wrapping, and
  decrypts them in-place.
- `clear_sensitive_fields(&mut self)` — zeroizes tagged `String` and
  `Option<String>` fields.
- `Drop` impl (when `zeroize` feature is enabled, the default) — calls
  `clear_sensitive_fields()` on drop.

**Algorithm note:** The default is `PBEWithHMACSHA512AndAES_256`.
Specify a different algorithm per field with
`#[rasypt(encrypted, algorithm = "PBEWithHMACSM3AndSM4_GCM")]`. The value must
be a valid [`Algorithm`](rasypt_lite_lib::Algorithm) variant name. Different
fields can use different algorithms.

## Example

```rust
use rasypt_lite_derive::RasyptDecrypt;

#[derive(RasyptDecrypt)]
struct Config {
    username: String,

    // AES-256-CBC (default)
    #[rasypt(encrypted)]
    password: Option<String>,

    // SM4-GCM
    #[rasypt(encrypted, algorithm = "PBEWithHMACSM3AndSM4_GCM")]
    api_key: String,
}

let mut cfg = Config {
    username: "user".into(),
    password: Some("ENC(...)".into()),
    api_key: "ENC(...)".into(),
};

cfg.decrypt_enc_fields("mypassword")?;
// cfg.password and cfg.api_key are now decrypted

cfg.clear_sensitive_fields();
// tagged fields zeroized
```
```

## Supported field types

Only `String` and `Option<String>`. Tagging any other type with
`#[rasypt(encrypted)]` is a compile-time error. Only named struct fields
are supported.

## Features

- `zeroize` (default) — generates a `Drop` impl that auto-clears tagged
  fields. Disable in `Cargo.toml` if you prefer manual clearing:
  ```toml
  [dependencies.rasypt-lite-derive]
  version = "1"
  default-features = false
  ```

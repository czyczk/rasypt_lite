# rasypt-lite-derive

Procedural macro crate that provides `#[derive(RasyptDecrypt)]`.

When you derive `RasyptDecrypt` on a struct it generates two public methods
and, when the `zeroize` feature is enabled (the default), a `Drop`
implementation:

* `decrypt_enc_fields(&mut self, password: &str) -> Result<(), Error>` — walks
  every `String` and `Option<String>` field and if the value is wrapped with
  `ENC(...)` it will attempt to decrypt it, returning the first error
  encountered.
* `clear_sensitive_fields(&mut self)` — zeroizes/clears all `String` and
  `Option<String>` fields; useful to call manually when you want to remove
  secrets.
* `Drop` impl (behind `zeroize` feature) — automatically calls
  `clear_sensitive_fields()` during destruction so that secrets are erased
  when the value goes out of scope.

## Simple example

```rust
use rasypt_lite_derive::RasyptDecrypt;

#[derive(RasyptDecrypt)]
struct Config {
    pub username: String,
    pub password: Option<String>,
}

let mut cfg = Config {
    username: "user".into(),
    password: Some("ENC(...)".into()),
};

// decrypt all encrypted fields
cfg.decrypt_enc_fields("mypassword")?;

// optional: clear them when you're finished
cfg.clear_sensitive_fields();
```

The macro currently only supports named struct fields and will panic at
compile time if applied to tuple structs, enums, or other unsupported types.

See the root workspace `README.md` for a minimal overview and the
`rasypt-lite-cli/README.md` for CLI usage details.

## Features

* `zeroize` – automatically implemented by default; disable it in your
  `Cargo.toml` if you prefer to manage clearing yourself.

## Notes

This crate re-exports `rasypt_lite_lib::Error` for convenience.  The
`decrypt_enc_fields` method propagates all errors, including
`Error::NotEncValue`, so you can detect unwrapped values.

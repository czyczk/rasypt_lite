# rasypt-lite CLI

The `rasypt-lite` command‑line utility is a thin wrapper around
the `rasypt-lite-lib` encryption/decryption library. It allows you to
encrypt or decrypt strings from a shell or script without writing any Rust
code.

## Installation

Build the tool with `cargo install --path rasypt-lite-cli` or include it as
part of a workspace build.

## Usage

```text
USAGE:
    rasypt-lite <SUBCOMMAND>

COMMANDS:
    encrypt    encrypt one or more values
    decrypt    decrypt one or more values
    --help     Print help information
```

### Examples

Encrypt a literal string:

```sh
rasypt-lite encrypt --password mypass "top secret"
```

Decrypt an `ENC(...)` wrapped value:

```sh
rasypt-lite decrypt --password mypass "ENC(abcd...)"
```

If you pass a short password (fewer than 8 characters), the CLI prints a warning
to `stderr` but still proceeds. To silence that warning, use `--quiet`.

```sh
rasypt-lite --quiet encrypt --password pwd "top secret"
```

By default the password is prompted from `stdin`; you can also supply it via
the `--password` flag or from a file.

Refer to the source code in `rasypt-lite-cli/src/main.rs` for documentation of
additional command‑line options such as setting the PBKDF2 iteration count or
processing files.

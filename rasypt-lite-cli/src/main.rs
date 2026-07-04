use clap::{Args, Parser, Subcommand};
use rasypt_lite_lib::Algorithm;
use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
};

const MIN_RECOMMENDED_PASSWORD_LEN: usize = 8;
const ENC_PREFIX: &str = "ENC(";
const DEC_PREFIX: &str = "DEC(";

#[derive(Parser)]
#[command(
    name = "rasypt-lite",
    about = "Password-based encryption with PBEWithHMACSHA512AndAES_256 and SM-compliant algorithms",
    version
)]
struct Cli {
    /// Silence non-fatal warnings
    #[arg(short, long, default_value_t = false, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args)]
struct InputSource {
    /// Literal value to process
    #[arg(short, long, conflicts_with = "file", required_unless_present = "file")]
    input: Option<String>,
    /// Path to a UTF-8 text file to process
    #[arg(
        short = 'f',
        long = "file",
        visible_alias = "path",
        conflicts_with = "input",
        required_unless_present = "input"
    )]
    file: Option<String>,
    /// Overwrite the source file instead of writing the transformed content to stdout
    #[arg(long, default_value_t = false, requires = "file")]
    in_place: bool,
}

impl InputSource {
    fn into_mode(self) -> InputMode {
        match self.file {
            Some(path) => InputMode::File {
                path,
                in_place: self.in_place,
            },
            None => InputMode::Literal(
                self.input
                    .expect("clap should require either --input or --file"),
            ),
        }
    }
}

enum InputMode {
    Literal(String),
    File { path: String, in_place: bool },
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a plaintext value
    Encrypt {
        #[command(flatten)]
        source: InputSource,
        /// Password for key derivation
        #[arg(short, long)]
        password: String,
        /// Wrap output in ENC(...)
        #[arg(long, default_value_t = false, conflicts_with = "file")]
        wrap: bool,
        /// Algorithm to use (default: PBEWithHMACSHA512AndAES_256)
        #[arg(
            short = 'a',
            long = "algorithm",
            alias = "alg",
            default_value = "PBEWithHMACSHA512AndAES_256",
            value_parser = clap::value_parser!(Algorithm)
        )]
        algorithm: Algorithm,
        /// PBKDF2 iteration count (overrides algorithm default)
        #[arg(long = "iterations")]
        iterations: Option<u32>,
    },
    /// Decrypt an encrypted value
    Decrypt {
        #[command(flatten)]
        source: InputSource,
        /// Password for key derivation
        #[arg(short, long)]
        password: String,
        /// Algorithm used during encryption (default: PBEWithHMACSHA512AndAES_256)
        #[arg(
            short = 'a',
            long = "algorithm",
            alias = "alg",
            default_value = "PBEWithHMACSHA512AndAES_256",
            value_parser = clap::value_parser!(Algorithm)
        )]
        algorithm: Algorithm,
        /// PBKDF2 iteration count (overrides algorithm default)
        #[arg(long = "iterations")]
        iterations: Option<u32>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt {
            source,
            password,
            wrap,
            algorithm,
            iterations,
        } => {
            warn_if_password_too_short(&password, cli.quiet);
            run_encrypt(source.into_mode(), &password, wrap, algorithm, iterations)
        }
        Commands::Decrypt {
            source,
            password,
            algorithm,
            iterations,
        } => {
            warn_if_password_too_short(&password, cli.quiet);
            run_decrypt(source.into_mode(), &password, algorithm, iterations)
        }
    };

    match result {
        Ok(Some(output)) => write_stdout(&output),
        Ok(None) => {}
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(1);
        }
    }
}

fn warn_if_password_too_short(password: &str, quiet: bool) {
    if quiet || password.chars().count() >= MIN_RECOMMENDED_PASSWORD_LEN {
        return;
    }

    eprintln!(
        "Warning: password length is below the recommended {} characters; continuing anyway. Use --quiet to suppress this warning.",
        MIN_RECOMMENDED_PASSWORD_LEN
    );
}

fn run_encrypt(
    source: InputMode,
    password: &str,
    wrap: bool,
    algorithm: Algorithm,
    iterations: Option<u32>,
) -> Result<Option<String>, String> {
    match source {
        InputMode::Literal(input) => {
            let encrypted = encrypt_value(algorithm, password, &input, iterations);
            if wrap && algorithm == Algorithm::PBEWithHMACSHA512AndAES_256 {
                Ok(Some(format!("{ENC_PREFIX}{encrypted})")))
            } else {
                if wrap {
                    eprintln!(
                        "Warning: --wrap is only supported with the default algorithm; output not wrapped."
                    );
                }
                Ok(Some(encrypted))
            }
        }
        InputMode::File { path, in_place } => process_file(&path, in_place, |content| {
            encrypt_file_contents(algorithm, password, content, iterations)
        })
        .map_err(|error| format!("Encryption failed: {error}")),
    }
}

fn run_decrypt(
    source: InputMode,
    password: &str,
    algorithm: Algorithm,
    iterations: Option<u32>,
) -> Result<Option<String>, String> {
    match source {
        InputMode::Literal(input) => decrypt_cli_input(algorithm, password, &input, iterations)
            .map(Some)
            .map_err(|error| format!("Decryption failed: {error}")),
        InputMode::File { path, in_place } => process_file(&path, in_place, |content| {
            decrypt_file_contents(algorithm, password, content, iterations)
        })
        .map_err(|error| format!("Decryption failed: {error}")),
    }
}

fn encrypt_value(
    algorithm: Algorithm,
    password: &str,
    input: &str,
    iterations: Option<u32>,
) -> String {
    match iterations {
        Some(it) => rasypt_lite_lib::encrypt_with_iterations(algorithm, password, input, it),
        None => rasypt_lite_lib::encrypt_with(algorithm, password, input),
    }
}

fn decrypt_value(
    algorithm: Algorithm,
    password: &str,
    input: &str,
    iterations: Option<u32>,
) -> Result<String, rasypt_lite_lib::Error> {
    match iterations {
        Some(it) => rasypt_lite_lib::decrypt_with_iterations(algorithm, password, input, it),
        None => rasypt_lite_lib::decrypt_with(algorithm, password, input),
    }
}

fn decrypt_cli_input(
    algorithm: Algorithm,
    password: &str,
    input: &str,
    iterations: Option<u32>,
) -> Result<String, rasypt_lite_lib::Error> {
    if rasypt_lite_lib::is_enc_value(input) {
        let inner = unwrap_marker(input, ENC_PREFIX).expect("validated ENC wrapper");
        return decrypt_value(algorithm, password, inner, iterations);
    }

    decrypt_value(algorithm, password, input, iterations)
}

fn encrypt_file_contents(
    algorithm: Algorithm,
    password: &str,
    content: &str,
    iterations: Option<u32>,
) -> Result<String, String> {
    transform_marked_values(content, DEC_PREFIX, ENC_PREFIX, |plaintext| {
        Ok(encrypt_value(algorithm, password, plaintext, iterations))
    })
}

fn decrypt_file_contents(
    algorithm: Algorithm,
    password: &str,
    content: &str,
    iterations: Option<u32>,
) -> Result<String, String> {
    transform_marked_values(content, ENC_PREFIX, DEC_PREFIX, |ciphertext| {
        decrypt_value(algorithm, password, ciphertext, iterations)
            .map_err(|error| error.to_string())
    })
}

fn process_file<F>(path: &str, in_place: bool, transform: F) -> Result<Option<String>, String>
where
    F: FnOnce(&str) -> Result<String, String>,
{
    let expanded = expand_tilde_path(path);
    let content = fs::read_to_string(&expanded)
        .map_err(|error| format!("failed to read {}: {error}", expanded.display()))?;
    let transformed = transform(&content)?;

    if in_place {
        fs::write(&expanded, transformed.as_bytes())
            .map_err(|error| format!("failed to write {}: {error}", expanded.display()))?;
        Ok(None)
    } else {
        Ok(Some(transformed))
    }
}

fn transform_marked_values<F, E>(
    input: &str,
    source_prefix: &str,
    target_prefix: &str,
    mut transform: F,
) -> Result<String, E>
where
    F: FnMut(&str) -> Result<String, E>,
{
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(offset) = input[cursor..].find(source_prefix) {
        let start = cursor + offset;
        output.push_str(&input[cursor..start]);

        let inner_start = start + source_prefix.len();
        let Some(inner_end) = find_marker_end(input, inner_start) else {
            output.push_str(&input[start..]);
            cursor = input.len();
            break;
        };

        let inner = &input[inner_start..inner_end];
        let transformed = transform(inner)?;
        output.push_str(target_prefix);
        output.push_str(&transformed);
        output.push(')');

        cursor = inner_end + 1;
    }

    output.push_str(&input[cursor..]);
    Ok(output)
}

fn find_marker_end(input: &str, inner_start: usize) -> Option<usize> {
    let mut depth = 1usize;

    for (offset, ch) in input[inner_start..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(inner_start + offset);
                }
            }
            _ => {}
        }
    }

    None
}

fn unwrap_marker<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let trimmed = input.trim();
    trimmed
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(')'))
}

fn expand_tilde_path(path: &str) -> PathBuf {
    if path == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from(path));
    }

    if let Some(stripped) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = home_dir() {
            return home.join(stripped);
        }
    }

    PathBuf::from(path)
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .or_else(|| {
            let home_drive = env::var_os("HOMEDRIVE")?;
            let home_path = env::var_os("HOMEPATH")?;
            let mut home = PathBuf::from(home_drive);
            home.push(home_path);
            Some(home)
        })
}

fn write_stdout(value: &str) {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(value.as_bytes())
        .expect("failed to write CLI output");
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "password123";
    const TEST_PLAINTEXT: &str = "hello world";

    #[test]
    fn decrypt_accepts_wrapped_value_for_explicit_algorithm() {
        let encrypted = rasypt_lite_lib::encrypt_with(
            Algorithm::PBEWithHMACSM3AndSM4_GCM,
            TEST_PASSWORD,
            TEST_PLAINTEXT,
        );

        let plaintext = decrypt_cli_input(
            Algorithm::PBEWithHMACSM3AndSM4_GCM,
            TEST_PASSWORD,
            &format!("ENC({encrypted})"),
            None,
        )
        .unwrap();

        assert_eq!(plaintext, TEST_PLAINTEXT);
    }

    #[test]
    fn decrypt_accepts_bare_value_for_explicit_algorithm() {
        let encrypted = rasypt_lite_lib::encrypt_with(
            Algorithm::PBEWithHMACSM3AndSM4_CBC,
            TEST_PASSWORD,
            TEST_PLAINTEXT,
        );

        let plaintext = decrypt_cli_input(
            Algorithm::PBEWithHMACSM3AndSM4_CBC,
            TEST_PASSWORD,
            &encrypted,
            None,
        )
        .unwrap();

        assert_eq!(plaintext, TEST_PLAINTEXT);
    }

    #[test]
    fn file_mode_round_trip_preserves_plain_text_and_nested_parentheses() {
        let original = "plain=keep\nfirst=DEC(alpha)\nsecond=DEC(beta(gamma))";

        let encrypted = encrypt_file_contents(
            Algorithm::PBEWithHMACSM3AndSM4_GCM,
            TEST_PASSWORD,
            original,
            None,
        )
        .unwrap();

        assert!(encrypted.contains("plain=keep"));
        assert_eq!(encrypted.matches("ENC(").count(), 2);
        assert!(!encrypted.contains("DEC(alpha)"));

        let decrypted = decrypt_file_contents(
            Algorithm::PBEWithHMACSM3AndSM4_GCM,
            TEST_PASSWORD,
            &encrypted,
            None,
        )
        .unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn unmatched_markers_are_left_untouched() {
        let input = "before DEC(secret after";

        let output = transform_marked_values(input, DEC_PREFIX, ENC_PREFIX, |value| {
            Ok::<_, ()>(value.to_owned())
        })
        .unwrap();

        assert_eq!(output, input);
    }
}

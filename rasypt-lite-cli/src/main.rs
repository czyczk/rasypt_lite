use clap::{Parser, Subcommand};
use rasypt_lite_lib::Algorithm;

const MIN_RECOMMENDED_PASSWORD_LEN: usize = 8;

#[derive(Parser)]
#[command(
    name = "rasypt-lite",
    about = "Password-based encryption with PBEWithHMACSHA512AndAES_256 and SM-compliant algorithms"
)]
struct Cli {
    /// Silence non-fatal warnings
    #[arg(short, long, default_value_t = false, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a plaintext value
    Encrypt {
        /// Plaintext to encrypt
        #[arg(short, long)]
        input: String,
        /// Password for key derivation
        #[arg(short, long)]
        password: String,
        /// Wrap output in ENC(...)
        #[arg(long, default_value_t = false)]
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
        /// The Base64-encoded ciphertext (or ENC(...) wrapped)
        #[arg(short, long)]
        input: String,
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

    match cli.command {
        Commands::Encrypt {
            input,
            password,
            wrap,
            algorithm,
            iterations,
        } => {
            warn_if_password_too_short(&password, cli.quiet);
            let encrypted = match iterations {
                Some(it) => {
                    rasypt_lite_lib::encrypt_with_iterations(algorithm, &password, &input, it)
                }
                None => rasypt_lite_lib::encrypt_with(algorithm, &password, &input),
            };
            if wrap && algorithm == Algorithm::PBEWithHMACSHA512AndAES_256 {
                println!("ENC({})", encrypted);
            } else if wrap {
                eprintln!("Warning: --wrap is only supported with the default algorithm; output not wrapped.");
                println!("{}", encrypted);
            } else {
                println!("{}", encrypted);
            }
        }
        Commands::Decrypt {
            input,
            password,
            algorithm,
            iterations,
        } => {
            warn_if_password_too_short(&password, cli.quiet);

            let result = if algorithm == Algorithm::PBEWithHMACSHA512AndAES_256
                && rasypt_lite_lib::is_enc_value(&input)
            {
                rasypt_lite_lib::decrypt_enc(&input, &password)
            } else {
                match iterations {
                    Some(it) => rasypt_lite_lib::decrypt_with_iterations(
                        algorithm, &password, &input, it,
                    ),
                    None => rasypt_lite_lib::decrypt_with(algorithm, &password, &input),
                }
            };
            match result {
                Ok(plaintext) => println!("{}", plaintext),
                Err(e) => {
                    eprintln!("Decryption failed: {}", e);
                    std::process::exit(1);
                }
            }
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

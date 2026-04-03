use clap::{Parser, Subcommand};

const MIN_RECOMMENDED_PASSWORD_LEN: usize = 8;

#[derive(Parser)]
#[command(
    name = "rasypt-lite",
    about = "Jasypt-compatible AES-256 encryption/decryption (PBEWITHHMACSHA512ANDAES_256)"
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
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        password: String,
        /// Wrap output in ENC(...)
        #[arg(long, default_value_t = false)]
        wrap: bool,
    },
    /// Decrypt an encrypted value
    Decrypt {
        /// The Base64-encoded ciphertext (or ENC(...) wrapped)
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        password: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            password,
            wrap,
        } => {
            warn_if_password_too_short(&password, cli.quiet);
            let encrypted = rasypt_lite_lib::encrypt(&input, &password);
            if wrap {
                println!("ENC({})", encrypted);
            } else {
                println!("{}", encrypted);
            }
        }
        Commands::Decrypt { input, password } => {
            warn_if_password_too_short(&password, cli.quiet);
            let result = if rasypt_lite_lib::is_enc_value(&input) {
                rasypt_lite_lib::decrypt_enc(&input, &password)
            } else {
                rasypt_lite_lib::decrypt(&input, &password)
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

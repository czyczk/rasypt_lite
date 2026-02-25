use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "rasypt-lite",
    about = "Jasypt-compatible AES-256 encryption/decryption (PBEWITHHMACSHA512ANDAES_256)"
)]
struct Cli {
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
            let encrypted = rasypt_lite_lib::encrypt(&input, &password);
            if wrap {
                println!("ENC({})", encrypted);
            } else {
                println!("{}", encrypted);
            }
        }
        Commands::Decrypt { input, password } => {
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

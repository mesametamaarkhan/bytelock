use clap::{Parser, Subcommand};
mod vault;
mod crypto;

#[derive(Parser)]
#[command(name = "bytelock")]
#[command(version = "0.1")]
#[command(about = "A simple Rust password manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add { name: String },
    Get { name: String },
    List,
}

fn verify_master(vault: &vault::Vault, password: &str) -> Result<[u8;32], String> {
    let key = crypto::derive_key(password, &vault.header.salt)?;

    // Convert nonce to array
    let mut nonce_arr = [0u8; 24];
    nonce_arr.copy_from_slice(&vault.header.verif_nonce);

    // Attempt to decrypt verification token
    let check = crypto::decrypt(
        &key,
        &vault.header.verif_ciphertext,
        &nonce_arr
    )?;

    if check != b"bytelock-check" {
        return Err("Invalid master password".into());
    }

    Ok(key)
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            let password = rpassword::prompt_password("Create master password: ")
                .expect("Failed to read password");

            vault::create_new_vault(&password)
                .expect("Failed to initialize vault");

            println!("Vault created successfully.");
        }

        Commands::Add { name } => {
            let mut vault = vault::load_vault("vault.json")
                .expect("Failed to load vault");

            let master = rpassword::prompt_password("Master password: ")
                .expect("Failed to read password");

            let key = match verify_master(&vault, &master) {
                Ok(key) => key,
                Err(_) => {
                    println!("Incorrect master password");
                    return;
                }
            };

            let pwd = rpassword::prompt_password("Enter password to store: ")
                .expect("Failed to read password");

            let (ciphertext, nonce) =
                crypto::encrypt(&key, pwd.as_bytes()).expect("Encryption failed");

            vault.entries.insert(
                name.clone(),
                vault::EncryptedEntry {
                    nonce: nonce.to_vec(),
                    ciphertext,
                },
            );

            vault::save_vault("vault.json", &vault)
                .expect("Failed to save vault");

            println!("Stored entry '{}'", name);
        }

        Commands::Get { name } => {
            let vault = vault::load_vault("vault.json")
                .expect("Failed to load vault");

            let master = rpassword::prompt_password("Master password: ")
                .expect("Failed to read password");

            let key = match verify_master(&vault, &master) {
                Ok(key) => key,
                Err(_) => {
                    println!("Incorrect master password");
                    return;
                }
            };

            let entry = match vault.entries.get(&name) {
                Some(e) => e,
                None => {
                    println!("No such entry '{}'", name);
                    return;
                }
            };

            let mut nonce_arr = [0u8; 24];
            nonce_arr.copy_from_slice(&entry.nonce);

            let plaintext =
                crypto::decrypt(&key, &entry.ciphertext, &nonce_arr).expect("Decryption failed");

            let password = String::from_utf8(plaintext)
                .expect("Stored password is not valid UTF-8");

            println!("Password for '{}': {}", name, password);
        }

        Commands::List => {
            let vault = vault::load_vault("vault.json")
                .expect("Failed to load vault");

            println!("Entries:");
            for name in vault.entries.keys() {
                println!("- {}", name);
            }
        }
    }
}

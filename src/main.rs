// main.rs
use clap::{Parser, Subcommand, Args};
mod vault;
mod crypto;

use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "bytelock")]
#[command(version = "0.1")]
#[command(about = "A simple Rust password manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Clone, Debug)]
struct AddArgs {
    name: String,
    /// Overwrite existing entry without prompting
    #[arg(short, long)]
    force: bool,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add(AddArgs),
    Get { name: String },
    List,
    Remove { name: String },
    Update { name: String },
    Passwd,
}

fn verify_master(vault: &vault::Vault, password: &str) -> Result<[u8;32], String> {
    // Use KDF params stored in header (if present) or defaults
    let key = crypto::derive_key(password, &vault.header.salt, Some(&vault.header.kdf_params))?;

    // Convert nonce to array (ensure length)
    let mut nonce_arr = [0u8; 24];
    if vault.header.verif_nonce.len() != nonce_arr.len() {
        return Err("Invalid vault verification nonce length".into());
    }
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

fn prompt_confirm(prompt: &str) -> bool {
    print!("{} [y/N]: ", prompt);
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
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

        Commands::Add(args) => {
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

            if vault.entries.contains_key(&args.name) && !args.force {
                let want = prompt_confirm(&format!("Entry '{}' exists. Overwrite?", args.name));
                if !want {
                    println!("Aborted.");
                    return;
                }
            }

            let pwd = rpassword::prompt_password("Enter password to store: ")
                .expect("Failed to read password");

            // Zeroize the plaintext password bytes while using them
            let pwd_bytes = zeroize::Zeroizing::new(pwd.into_bytes());

            let (ciphertext, nonce) =
                crypto::encrypt(&key, pwd_bytes.as_ref()).expect("Encryption failed");

            vault.entries.insert(
                args.name.clone(),
                vault::EncryptedEntry {
                    nonce: nonce.to_vec(),
                    ciphertext,
                },
            );

            vault::save_vault("vault.json", &vault)
                .expect("Failed to save vault");

            println!("Stored entry '{}'", args.name);
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

            // Decrypt into a zeroizing buffer
            let plaintext =
                crypto::decrypt(&key, &entry.ciphertext, &nonce_arr).expect("Decryption failed");

            // Convert to String (we can't avoid creating a String for printing).
            let password = String::from_utf8(plaintext.clone())
                .expect("Stored password is not valid UTF-8");

            // Zero the plaintext bytes explicitly (Zeroizing drops here)
            let _zero = zeroize::Zeroizing::new(plaintext);

            println!("Password for '{}': {}", name, password);
        }

        Commands::List => {
            let vault = vault::load_vault("vault.json")
                .expect("Failed to load vault");

            let master = rpassword::prompt_password("Master password: ")
                .expect("failed to read password");

            match verify_master(&vault, &master) {
                Ok(_) => {},
                Err(_) => {
                    println!("Incorrect master password");
                    return;
                }
            }

            println!("Entries:");
            for name in vault.entries.keys() {
                println!("- {}", name);
            }
        }

        Commands::Remove { name } => {
            let mut vault = vault::load_vault("vault.json")
                .expect("failed to load vault");

            let master = rpassword::prompt_password("Master password: ")
                .expect("failed to read password");

            match verify_master(&vault, &master) {
                Ok(_) => {},
                Err(_) => {
                    println!("Incorrect master password");
                    return;
                }
            }

            let removed = vault.entries.remove(&name);

            match removed {
                Some(_) => {
                    vault::save_vault("vault.json", &vault)
                        .expect("Failed to save vault");

                    println!("Removed entry '{}'", name);
                }
                None => {
                    println!("No such entry '{}'", name);
                }
            }
        }

        Commands::Update { name } => {
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

            if !vault.entries.contains_key(&name) {
                println!("No such entry '{}'", name);
                return;
            }

            let pwd = rpassword::prompt_password("Enter new password to store: ")
                .expect("Failed to read password");

            let pwd_bytes = zeroize::Zeroizing::new(pwd.into_bytes());

            let (ciphertext, nonce) =
                crypto::encrypt(&key, pwd_bytes.as_ref()).expect("Encryption failed");

            vault.entries.insert(
                name.clone(),
                vault::EncryptedEntry {
                    nonce: nonce.to_vec(),
                    ciphertext,
                },
            );

            vault::save_vault("vault.json", &vault)
                .expect("Failed to save vault");

            println!("Updated entry '{}'", name);
        }

        Commands::Passwd => {
            // Change master password: decrypt everything with old key, re-encrypt with new key,
            // update salt, kdf_params, and verification ciphertext/nonce.
            let mut vault = vault::load_vault("vault.json")
                .expect("Failed to load vault");

            let old = rpassword::prompt_password("Old master password: ")
                .expect("Failed to read password");

            // Verify old
            let old_key = match verify_master(&vault, &old) {
                Ok(k) => k,
                Err(_) => {
                    println!("Incorrect master password");
                    return;
                }
            };

            let new = rpassword::prompt_password("New master password: ")
                .expect("Failed to read password");
            let new2 = rpassword::prompt_password("Confirm new master password: ")
                .expect("Failed to read password");

            if new != new2 {
                println!("New passwords do not match.");
                return;
            }

            // perform re-encryption using vault helper
            match vault::change_master_password(&mut vault, &old_key, &new) {
                Ok(_) => {
                    vault::save_vault("vault.json", &vault)
                        .expect("Failed to save vault");
                    println!("Master password updated successfully.");
                }
                Err(e) => {
                    println!("Failed to change master password: {}", e);
                }
            }
        }
    }
}

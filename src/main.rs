// src/main.rs
use clap::{Parser, Subcommand, Args};
mod vault;
mod crypto;

use std::io::{self, Write};
use rand::RngCore;

/// ByteLock - small CLI password manager
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
    /// Initialize a new vault
    Init,

    /// Add an entry (password will be prompted)
    Add(AddArgs),

    /// Get and print an entry's password; use --copy to copy to clipboard for 10s
    Get {
        name: String,
        #[arg(short, long)]
        copy: bool,
    },

    /// List all entries
    List,

    /// Remove an entry
    Remove { name: String },

    /// Update an existing entry (prompt for new password)
    Update { name: String },

    /// Change master password (re-encrypts vault)
    Passwd,

    /// Generate a password
    Gen {
        /// Length of the generated password
        #[arg(short, long, default_value_t = 16)]
        length: usize,
        /// Exclude uppercase characters
        #[arg(long)]
        no_uppercase: bool,
        /// Exclude lowercase characters
        #[arg(long)]
        no_lowercase: bool,
        /// Exclude digits
        #[arg(long)]
        no_digits: bool,
        /// Exclude symbols
        #[arg(long)]
        no_symbols: bool,
        /// Exclude ambiguous characters like 'Il1O0'
        #[arg(long)]
        exclude_ambiguous: bool,
        /// Copy generated password to clipboard for 10 seconds
        #[arg(short, long)]
        copy: bool,
    },
}

fn prompt_yes(prompt: &str) -> bool {
    print!("{} [y/N]: ", prompt);
    io::stdout().flush().ok();
    let mut s = String::new();
    if io::stdin().read_line(&mut s).is_err() {
        return false;
    }
    matches!(s.trim().to_lowercase().as_str(), "y" | "yes")
}

fn copy_to_clipboard_with_timeout(text: &str, secs: u64) -> Result<(), String> {
    use clipboard::{ClipboardContext, ClipboardProvider};
    use std::time::Duration;

    // Set clipboard immediately
    let mut ctx: ClipboardContext = ClipboardProvider::new()
        .map_err(|e| format!("Clipboard init error: {}", e))?;
    ctx.set_contents(text.to_string())
        .map_err(|e| format!("Clipboard set error: {}", e))?;

    // Spawn a thread to clear the clipboard after timeout
    let text_clone = text.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));

        // Explicitly annotate ctx2 type
        let ctx2_result: Result<ClipboardContext, _> = ClipboardProvider::new();
        if let Ok(mut ctx2) = ctx2_result {
            // Explicitly annotate type of current
            let current_result: Result<String, _> = ctx2.get_contents();
            if let Ok(current) = current_result {
                if current == text_clone {
                    let _ = ctx2.set_contents("".to_string());
                }
            }
        }
    });

    Ok(())
}

/// Verify master password; returns derived key if OK
fn verify_master(vault: &vault::Vault, password: &str) -> Result<[u8;32], String> {
    let key = crypto::derive_key(password, &vault.header.salt, Some(&vault.header.kdf_params))?;

    let mut nonce_arr = [0u8; 24];
    if vault.header.verif_nonce.len() != nonce_arr.len() {
        return Err("Invalid vault verification nonce length".into());
    }
    nonce_arr.copy_from_slice(&vault.header.verif_nonce);

    let check = crypto::decrypt(&key, &vault.header.verif_ciphertext, &nonce_arr)?;

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

        Commands::Add(args) => {
            let mut vault = vault::load_vault("vault.json")
                .expect("Failed to load vault");

            let master = rpassword::prompt_password("Master password: ")
                .expect("Failed to read password");

            let key = match verify_master(&vault, &master) {
                Ok(k) => k,
                Err(_) => {
                    println!("Incorrect master password");
                    return;
                }
            };

            if vault.entries.contains_key(&args.name) && !args.force {
                let ok = prompt_yes(&format!("Entry '{}' exists. Overwrite?", args.name));
                if !ok {
                    println!("Aborted.");
                    return;
                }
            }

            let pwd = rpassword::prompt_password("Enter password to store: ")
                .expect("Failed to read password");
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

        Commands::Get { name, copy } => {
            let vault = vault::load_vault("vault.json")
                .expect("Failed to load vault");

            let master = rpassword::prompt_password("Master password: ")
                .expect("Failed to read password");

            let key = match verify_master(&vault, &master) {
                Ok(k) => k,
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

            let password = String::from_utf8(plaintext.clone())
                .expect("Stored password is not valid UTF-8");

            // zeroize plaintext buffer when dropped
            let _zero = zeroize::Zeroizing::new(plaintext);

            println!("Password for '{}': {}", name, password);

            if copy {
                match copy_to_clipboard_with_timeout(&password, 10) {
                    Ok(_) => println!("Password copied to clipboard for 10s."),
                    Err(e) => println!("Failed to copy to clipboard: {}", e),
                }
            }
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
                Ok(k) => k,
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
            // Load vault, verify old password, re-encrypt everything with new password,
            // write a .bak file before overwriting.
            let mut vault = vault::load_vault("vault.json")
                .expect("Failed to load vault");

            let old = rpassword::prompt_password("Old master password: ")
                .expect("Failed to read password");

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

            // Create backup
            if std::path::Path::new("vault.json").exists() {
                let mut bak_name = "vault.json.bak".to_string();
                // Avoid clobbering an existing .bak by appending a random suffix if needed
                if std::path::Path::new(&bak_name).exists() {
                    let mut suffix = [0u8; 4];
                    rand::rngs::OsRng.fill_bytes(&mut suffix);
                    bak_name = format!("vault.json.bak.{:x}", u32::from_ne_bytes(suffix));
                }
                std::fs::copy("vault.json", &bak_name).ok();
                println!("Backup written to {}", bak_name);
            }

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

        Commands::Gen {
            length,
            no_uppercase,
            no_lowercase,
            no_digits,
            no_symbols,
            exclude_ambiguous,
            copy,
        } => {
            let pwd = generate_password(
                length,
                !no_uppercase,
                !no_lowercase,
                !no_digits,
                !no_symbols,
                exclude_ambiguous,
            );

            println!("{}", pwd);

            if copy {
                match copy_to_clipboard_with_timeout(&pwd, 10) {
                    Ok(_) => println!("Generated password copied to clipboard for 10s."),
                    Err(e) => println!("Failed to copy to clipboard: {}", e),
                }
            }
        }
    }
}

/// Simple configurable password generator
fn generate_password(
    length: usize,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool,
) -> String {
    const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &str = "0123456789";
    const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?";

    const AMBIGUOUS: &str = "Il1O0";

    let mut charset = String::new();
    if use_upper {
        charset.push_str(UPPER);
    }
    if use_lower {
        charset.push_str(LOWER);
    }
    if use_digits {
        charset.push_str(DIGITS);
    }
    if use_symbols {
        charset.push_str(SYMBOLS);
    }

    if charset.is_empty() {
        // fallback to a safe set
        charset.push_str(LOWER);
        charset.push_str(DIGITS);
    }

    if exclude_ambiguous {
        charset.retain(|c| !AMBIGUOUS.contains(c));
    }

    let mut rng = rand::rngs::OsRng;
    let mut out = String::with_capacity(length);
    let bytes = charset.as_bytes();
    let n = bytes.len();
    while out.len() < length {
        let mut rand_u = [0u8; 8];
        rng.fill_bytes(&mut rand_u);
        let mut val = u64::from_ne_bytes(rand_u);
        // generate several chars from val
        for _ in 0..8 {
            if out.len() >= length { break; }
            let idx = (val % (n as u64)) as usize;
            out.push(bytes[idx] as char);
            val /= n as u64;
            if val == 0 {
                // refill
                rng.fill_bytes(&mut rand_u);
                val = u64::from_ne_bytes(rand_u);
            }
        }
    }
    out
}

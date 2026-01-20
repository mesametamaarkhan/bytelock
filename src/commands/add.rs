//! Add a new entry to the vault.

use crate::{cli::AddArgs, crypto, vault, ui};
use zeroize::Zeroizing;

pub fn run(args: AddArgs) {
    let mut vault = vault::load_vault("vault.json")
        .expect("Failed to load vault");

    let master = rpassword::prompt_password("Master password: ")
        .expect("Failed to read password");

    let key = match crate::auth::verify_master(&vault, &master) {
        Ok(k) => k,
        Err(_) => {
            println!("Incorrect master password");
            return;
        }
    };

    if vault.entries.contains_key(&args.name) && !args.force {
        if !ui::prompt_yes(&format!("Entry '{}' exists. Overwrite?", args.name)) {
            println!("Aborted.");
            return;
        }
    }

    let pwd = rpassword::prompt_password("Enter password to store: ")
        .expect("Failed to read password");

    let pwd_bytes = Zeroizing::new(pwd.into_bytes());

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

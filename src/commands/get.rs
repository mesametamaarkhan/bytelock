//! Retrieve and display an entry from the vault.

use crate::{crypto, ui, vault};

pub fn run(name: String, copy: bool) {
    let vault = vault::load_vault("vault.json")
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
        crypto::decrypt(&key, &entry.ciphertext, &nonce_arr)
            .expect("Decryption failed");

    let password =
        String::from_utf8(plaintext).expect("Stored password is not valid UTF-8");

    println!("Password for '{}': {}", name, password);

    if copy {
        if let Err(e) = ui::copy_to_clipboard_with_timeout(&password, 10) {
            println!("Failed to copy to clipboard: {}", e);
        }
    }
}

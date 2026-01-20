//! Change the master password for the vault.

use crate::vault;
use rand::RngCore;

pub fn run() {
    let mut vault = vault::load_vault("vault.json")
        .expect("Failed to load vault");

    let old = rpassword::prompt_password("Old master password: ")
        .expect("Failed to read password");

    let old_key = match crate::auth::verify_master(&vault, &old) {
        Ok(k) => k,
        Err(_) => {
            println!("Incorrect master password");
            return;
        }
    };

    let new = rpassword::prompt_password("New master password: ")
        .expect("Failed to read password");
    let confirm = rpassword::prompt_password("Confirm new master password: ")
        .expect("Failed to read password");

    if new != confirm {
        println!("New passwords do not match.");
        return;
    }

    if std::path::Path::new("vault.json").exists() {
        let mut bak = "vault.json.bak".to_string();
        if std::path::Path::new(&bak).exists() {
            let mut suffix = [0u8; 4];
            rand::rngs::OsRng.fill_bytes(&mut suffix);
            bak = format!("vault.json.bak.{:x}", u32::from_ne_bytes(suffix));
        }
        std::fs::copy("vault.json", &bak).ok();
        println!("Backup written to {}", bak);
    }

    match vault::change_master_password(&mut vault, &old_key, &new) {
        Ok(_) => {
            vault::save_vault("vault.json", &vault)
                .expect("Failed to save vault");
            println!("Master password updated successfully.");
        }
        Err(e) => println!("Failed to change master password: {}", e),
    }
}

//! List all entries in the vault.

use crate::vault;

pub fn run() {
    let vault = vault::load_vault("vault.json")
        .expect("Failed to load vault");

    let master = rpassword::prompt_password("Master password: ")
        .expect("Failed to read password");

    if crate::auth::verify_master(&vault, &master).is_err() {
        println!("Incorrect master password");
        return;
    }

    println!("Entries:");
    for name in vault.entries.keys() {
        println!("- {}", name);
    }
}

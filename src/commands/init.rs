//! Initialize a new ByteLock vault.

use crate::vault;

pub fn run() {
    let password = rpassword::prompt_password("Create master password: ")
        .expect("Failed to read password");

    vault::create_new_vault(&password)
        .expect("Failed to initialize vault");

    println!("Vault created successfully.");
}

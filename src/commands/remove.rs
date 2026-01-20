//! Remove an entry from the vault.

use crate::vault;

pub fn run(name: String) {
    let mut vault = vault::load_vault("vault.json")
        .expect("Failed to load vault");

    let master = rpassword::prompt_password("Master password: ")
        .expect("Failed to read password");

    if crate::auth::verify_master(&vault, &master).is_err() {
        println!("Incorrect master password");
        return;
    }

    match vault.entries.remove(&name) {
        Some(_) => {
            vault::save_vault("vault.json", &vault)
                .expect("Failed to save vault");
            println!("Removed entry '{}'", name);
        }
        None => println!("No such entry '{}'", name),
    }
}

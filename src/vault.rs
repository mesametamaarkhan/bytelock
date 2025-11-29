use rand::RngCore;
use serde::{Serialize, Deserialize};
use std::fs;

use crate::crypto;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultHeader {
    pub version: u32,
    pub salt: Vec<u8>,

    // New fields for master password verification
    pub verif_nonce: Vec<u8>,
    pub verif_ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedEntry {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Vault {
    pub header: VaultHeader,
    pub entries: std::collections::HashMap<String, EncryptedEntry>,
}

impl VaultHeader {
    pub fn new_with_verification(key: &[u8; 32]) -> Self {
        let mut salt = vec![0u8; 16];
        rand::rng().fill_bytes(&mut salt);

        // Encrypt verification message using derived key
        let (ciphertext, nonce) = crypto::encrypt(key, b"bytelock-check")
            .expect("Failed to encrypt verification token");

        VaultHeader {
            version: 1,
            salt,
            verif_nonce: nonce.to_vec(),
            verif_ciphertext: ciphertext,
        }
    }
}

pub fn create_new_vault(master_password: &str) -> std::io::Result<Vault> {
    // First generate salt
    let mut salt = vec![0u8; 16];
    rand::rng().fill_bytes(&mut salt);

    // Derive key from master password + salt
    let key = crypto::derive_key(master_password, &salt)
        .expect("Key derivation failed");

    // Create header that includes verification token
    let (verif_ciphertext, verif_nonce) =
        crypto::encrypt(&key, b"bytelock-check").expect("Failed verification encryption");

    let header = VaultHeader {
        version: 1,
        salt,
        verif_nonce: verif_nonce.to_vec(),
        verif_ciphertext,
    };

    let vault = Vault {
        header,
        entries: std::collections::HashMap::new(),
    };

    save_vault("vault.json", &vault)?;
    Ok(vault)
}

pub fn load_vault(path: &str) -> std::io::Result<Vault> {
    let data = fs::read_to_string(path)?;
    let vault: Vault = serde_json::from_str(&data)?;
    Ok(vault)
}

pub fn save_vault(path: &str, vault: &Vault) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(vault)
        .expect("Failed to serialize vault");
    
    fs::write(path, json)
}

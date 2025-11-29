// vault.rs
use rand::RngCore;
use serde::{Serialize, Deserialize};
use std::fs;

use crate::crypto;

/// KDF parameters stored in the vault header (versionable)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KdfParams {
    /// Memory cost in kibibytes for Argon2 (e.g., 65536 = 64 MiB)
    pub memory_kib: u32,
    /// Iterations / time cost
    pub iterations: u32,
    /// Degree of parallelism (lanes)
    pub parallelism: u32,
    /// Desired derived key length in bytes (should be 32)
    pub hash_len: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            memory_kib: 65536, // 64 MiB
            iterations: 3,
            parallelism: 1,
            hash_len: 32,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultHeader {
    pub version: u32,
    pub salt: Vec<u8>,

    // New fields for master password verification
    pub verif_nonce: Vec<u8>,
    pub verif_ciphertext: Vec<u8>,

    // KDF parameters used to derive the master key
    #[serde(default)]
    pub kdf_params: KdfParams,
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
    #[allow(dead_code)]
    pub fn new_with_verification(key: &[u8; 32], kdf_params: KdfParams) -> Self {
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
            kdf_params,
        }
    }
}

pub fn create_new_vault(master_password: &str) -> std::io::Result<Vault> {
    // First generate salt
    let mut salt = vec![0u8; 16];
    rand::rng().fill_bytes(&mut salt);

    // Use default KDF params (explicit)
    let kdf_params = KdfParams::default();

    // Derive key from master password + salt
    let key = crypto::derive_key(master_password, &salt, Some(&kdf_params))
        .expect("Key derivation failed");

    // Create header that includes verification token
    let (verif_ciphertext, verif_nonce) =
        crypto::encrypt(&key, b"bytelock-check").expect("Failed verification encryption");

    let header = VaultHeader {
        version: 1,
        salt,
        verif_nonce: verif_nonce.to_vec(),
        verif_ciphertext,
        kdf_params,
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

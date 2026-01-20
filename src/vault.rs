//! Encrypted vault storage and master password management.
//!
//! This module defines the on-disk vault format and provides functions
//! for creating, loading, saving, and re-encrypting a vault.
//!
//! A vault consists of a header and a collection of encrypted entries.
//! The header stores cryptographic parameters, a random salt, and a
//! verification token encrypted under the derived master key.
//!
//! All passwords and secrets are encrypted using keys derived from a
//! user-supplied master password via Argon2id.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;

use crate::crypto;

/// Key derivation function (KDF) parameters stored in the vault header.
///
/// These parameters control how the master encryption key is derived
/// from the master password using Argon2id. They are stored alongside
/// the vault so future versions can adjust or migrate parameters safely.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KdfParams {
    /// Memory cost in kibibytes (e.g., 65536 = 64 MiB)
    pub memory_kib: u32,

    /// Number of iterations (time cost)
    pub iterations: u32,

    /// Degree of parallelism (number of lanes)
    pub parallelism: u32,

    /// Length of the derived key in bytes (typically 32)
    pub hash_len: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
            hash_len: 32,
        }
    }
}

/// Metadata stored at the beginning of a vault file.
///
/// The header contains all information required to derive the master
/// encryption key and verify that a provided master password is correct,
/// without revealing the password itself.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultHeader {
    /// Vault format version
    pub version: u32,

    /// Random salt used for key derivation
    pub salt: Vec<u8>,

    /// Nonce used to encrypt the verification token
    pub verif_nonce: Vec<u8>,

    /// Encrypted verification token used to validate the master password
    pub verif_ciphertext: Vec<u8>,

    /// Parameters used for the key derivation function
    #[serde(default)]
    pub kdf_params: KdfParams,
}

/// A single encrypted vault entry.
///
/// Each entry stores an independently encrypted secret along with
/// the nonce required for decryption.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedEntry {
    /// Nonce used during encryption
    pub nonce: Vec<u8>,

    /// Encrypted secret data
    pub ciphertext: Vec<u8>,
}

/// Complete vault structure stored on disk.
///
/// A vault consists of a header and a mapping of entry names to
/// encrypted secrets.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Vault {
    /// Vault metadata and cryptographic parameters
    pub header: VaultHeader,

    /// Encrypted entries indexed by name
    pub entries: std::collections::HashMap<String, EncryptedEntry>,
}

impl VaultHeader {
    /// Create a new vault header containing a verification token.
    ///
    /// The verification token is a fixed message encrypted under the
    /// derived master key. Successful decryption later proves that
    /// the correct master password was supplied.
    #[allow(dead_code)]
    pub fn new_with_verification(key: &[u8; 32], kdf_params: KdfParams) -> Self {
        let mut salt = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let (ciphertext, nonce) =
            crypto::encrypt(key, b"bytelock-check")
                .expect("Failed to encrypt verification token");

        Self {
            version: 1,
            salt,
            verif_nonce: nonce.to_vec(),
            verif_ciphertext: ciphertext,
            kdf_params,
        }
    }
}

/// Create a new vault initialized with a master password.
///
/// This function derives a master key from the provided password,
/// initializes the vault header with a verification token, and
/// writes the vault to disk.
pub fn create_new_vault(master_password: &str) -> std::io::Result<Vault> {
    let mut salt = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let kdf_params = KdfParams::default();

    let key = crypto::derive_key(master_password, &salt, Some(&kdf_params))
        .expect("Key derivation failed");

    let (verif_ciphertext, verif_nonce) =
        crypto::encrypt(&key, b"bytelock-check")
            .expect("Failed verification encryption");

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

/// Load a vault from disk.
///
/// The vault file is expected to be valid JSON matching the
/// current vault schema.
pub fn load_vault(path: &str) -> std::io::Result<Vault> {
    let data = fs::read_to_string(path)?;
    let vault = serde_json::from_str(&data)?;
    Ok(vault)
}

/// Save a vault to disk in pretty-printed JSON format.
pub fn save_vault(path: &str, vault: &Vault) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(vault)
        .expect("Failed to serialize vault");

    fs::write(path, json)
}

/// Change the master password and re-encrypt the entire vault.
///
/// All entries are first decrypted using the old derived key, then
/// re-encrypted using a new key derived from the new master password.
/// A new salt and verification token are generated as part of the process.
///
/// # Arguments
///
/// - `vault` — The vault to update in place
/// - `old_key` — The previously derived and verified master key
/// - `new_password` — The new master password in plaintext
pub fn change_master_password(
    vault: &mut Vault,
    old_key: &[u8; 32],
    new_password: &str,
) -> Result<(), String> {
    let mut decrypted_entries = std::collections::HashMap::new();

    for (name, entry) in &vault.entries {
        let mut nonce = [0u8; 24];
        if entry.nonce.len() != nonce.len() {
            return Err(format!("Invalid nonce length for entry '{}'", name));
        }

        nonce.copy_from_slice(&entry.nonce);

        let plaintext =
            crypto::decrypt(old_key, &entry.ciphertext, &nonce)
                .map_err(|e| format!("Failed to decrypt entry '{}': {}", name, e))?;

        decrypted_entries.insert(name.clone(), plaintext);
    }

    let mut new_salt = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut new_salt);

    let new_kdf = KdfParams::default();

    let new_key =
        crypto::derive_key(new_password, &new_salt, Some(&new_kdf))
            .map_err(|e| format!("Failed deriving new key: {}", e))?;

    let mut new_entries = std::collections::HashMap::new();

    for (name, plaintext) in decrypted_entries {
        let (ciphertext, nonce) =
            crypto::encrypt(&new_key, &plaintext)
                .map_err(|e| format!("Failed to encrypt entry '{}': {}", name, e))?;

        new_entries.insert(
            name,
            EncryptedEntry {
                nonce: nonce.to_vec(),
                ciphertext,
            },
        );
    }

    let (verif_ciphertext, verif_nonce) =
        crypto::encrypt(&new_key, b"bytelock-check")
            .map_err(|e| format!("Failed to re-encrypt verification token: {}", e))?;

    vault.header.salt = new_salt;
    vault.header.kdf_params = new_kdf;
    vault.header.verif_nonce = verif_nonce.to_vec();
    vault.header.verif_ciphertext = verif_ciphertext;
    vault.entries = new_entries;

    Ok(())
}

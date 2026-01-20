//! Authentication helpers for ByteLock.
//!
//! This module is responsible for verifying the master password and deriving
//! the symmetric encryption key used to access the vault.
//!
//! It provides a single source of truth for authentication logic and ensures
//! that:
//! - The master password is never stored
//! - Verification is done by decrypting a known token
//! - KDF parameters stored in the vault are respected

use rand::RngCore;

use crate::{crypto, vault};

/// Verify the master password against the vault header.
///
/// On success, returns the derived 32-byte master key.
/// On failure, returns an error indicating invalid authentication.
pub fn verify_master(vault: &vault::Vault, password: &str) -> Result<[u8; 32], String> {
    let key = crypto::derive_key(
        password,
        &vault.header.salt,
        Some(&vault.header.kdf_params),
    )?;

    let mut nonce = [0u8; 24];
    if vault.header.verif_nonce.len() != nonce.len() {
        return Err("Invalid vault verification nonce length".into());
    }
    nonce.copy_from_slice(&vault.header.verif_nonce);

    let plaintext =
        crypto::decrypt(&key, &vault.header.verif_ciphertext, &nonce)?;

    if plaintext != b"bytelock-check" {
        return Err("Invalid master password".into());
    }

    Ok(key)
}

pub fn generate_password(
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
        rng.try_fill_bytes(&mut rand_u);
        let mut val = u64::from_ne_bytes(rand_u);
        // generate several chars from val
        for _ in 0..8 {
            if out.len() >= length { break; }
            let idx = (val % (n as u64)) as usize;
            out.push(bytes[idx] as char);
            val /= n as u64;
            if val == 0 {
                // refill
                rng.try_fill_bytes(&mut rand_u);
                val = u64::from_ne_bytes(rand_u);
            }
        }
    }
    out
}
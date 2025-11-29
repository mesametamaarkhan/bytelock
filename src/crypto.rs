// src/crypto.rs
use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit},
    XNonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::vault::KdfParams;

/// Derive a 32-byte key from password and salt using Argon2id and explicit params.
/// Uses argon2::hash_password_into-style API (hash into raw bytes).
pub fn derive_key(password: &str, salt: &[u8], params_opt: Option<&KdfParams>) -> Result<[u8; 32], String> {
    let kdf = params_opt.cloned().unwrap_or_default();

    // Build Argon2 params
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(kdf.hash_len as usize),
    ).map_err(|e| format!("Invalid Argon2 params: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Zeroize password bytes while used
    let password_z = Zeroizing::new(password.as_bytes().to_vec());

    // Derive into buffer
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password_z.as_ref(), salt, &mut out)
        .map_err(|e| format!("Argon2 error: {}", e))?;

    Ok(out)
}

pub fn encrypt(key: &[u8;32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 24]), String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_struct = XNonce::from_slice(&nonce);

    let ciphertext = cipher.encrypt(nonce_struct, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok((ciphertext, nonce))
}

pub fn decrypt(key: &[u8;32], ciphertext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_struct = XNonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce_struct, ciphertext)
        .map_err(|_| "Decryption failed".to_string())?;

    Ok(plaintext)
}

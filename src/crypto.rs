//! Cryptographic primitives used by ByteLock.
//!
//! This module provides low-level cryptographic building blocks used
//! throughout the application. It is intentionally small and focused,
//! and does not perform any file I/O or user interaction.
//!
//! Responsibilities include:
//! - Deriving encryption keys from a master password using Argon2id
//! - Encrypting secrets using XChaCha20-Poly1305
//! - Decrypting encrypted data using the corresponding key and nonce
//!
//! All cryptographic operations rely on well-vetted algorithms and
//! libraries. Callers are responsible for supplying correct inputs
//! and handling sensitive data appropriately.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
    XNonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::vault::KdfParams;

/// Derive a fixed-size encryption key from a master password.
///
/// A 32-byte key is derived using Argon2id with the provided salt and
/// key derivation parameters. The derived key is suitable for use with
/// XChaCha20-Poly1305.
///
/// The password bytes are zeroized from memory after use.
///
/// # Arguments
///
/// - `password` — The master password in plaintext
/// - `salt` — A random salt unique to the vault
/// - `params_opt` — Optional Argon2id parameters; defaults are used if `None`
///
/// # Errors
///
/// Returns an error if the Argon2 parameters are invalid or if key
/// derivation fails.
pub fn derive_key(
    password: &str,
    salt: &[u8],
    params_opt: Option<&KdfParams>,
) -> Result<[u8; 32], String> {
    let kdf = params_opt.cloned().unwrap_or_default();

    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(kdf.hash_len as usize),
    )
    .map_err(|e| format!("Invalid Argon2 params: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let password_z = Zeroizing::new(password.as_bytes().to_vec());

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password_z.as_ref(), salt, &mut out)
        .map_err(|e| format!("Argon2 error: {}", e))?;

    Ok(out)
}

/// Encrypt plaintext using XChaCha20-Poly1305.
///
/// A fresh random nonce is generated for each encryption operation.
/// The returned ciphertext includes the authentication tag.
///
/// # Arguments
///
/// - `key` — A 32-byte encryption key
/// - `plaintext` — Data to encrypt
///
/// # Returns
///
/// A tuple containing the ciphertext and the generated nonce.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 24]), String> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok((ciphertext, nonce))
}

/// Decrypt ciphertext using XChaCha20-Poly1305.
///
/// The provided nonce must match the nonce used during encryption.
/// Authentication is verified as part of the decryption process.
///
/// # Arguments
///
/// - `key` — The 32-byte encryption key
/// - `ciphertext` — Encrypted data including the authentication tag
/// - `nonce` — Nonce used during encryption
///
/// # Errors
///
/// Returns an error if authentication fails or the data cannot be
/// decrypted.
pub fn decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| "Decryption failed".to_string())?;

    Ok(plaintext)
}

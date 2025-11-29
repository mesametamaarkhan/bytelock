use argon2::{Argon2, PasswordHasher};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit},
    XNonce,
};
use rand::RngCore;
use password_hash::SaltString;
use zeroize::Zeroizing;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let password = Zeroizing::new(password.as_bytes().to_vec());
    let salt = SaltString::encode_b64(salt)
        .map_err(|_| "Failed to encode salt".to_string())?;

    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_ref(), &salt)
        .map_err(|e| format!("Argon2 error: {}", e))?;

    let hash = password_hash.hash.ok_or("No hash output")?;
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    Ok(key)
}

pub fn encrypt(key: &[u8;32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 24]), String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce);
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

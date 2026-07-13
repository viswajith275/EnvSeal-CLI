use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;

/// One-time salt generation.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a 256-bit key from a password and salt using Argon2.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt `plaintext` with a freshly generated random nonce.
/// Returns `(nonce, ciphertext)`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(key.into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow!("encryption failed: {e}"))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt `ciphertext` using `key` and `nonce_bytes`.
pub fn decrypt(key: &[u8; KEY_LEN], nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm::new(key.into());

    if nonce_bytes.len() != NONCE_LEN {
        return Err(anyhow!("invalid nonce length: corrupted data"));
    }
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("decryption failed: wrong password or corrupted data"))?;

    String::from_utf8(plaintext).map_err(|e| anyhow!("decrypted data was not valid utf8: {e}"))
}
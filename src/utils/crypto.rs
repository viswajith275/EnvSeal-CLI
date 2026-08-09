use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;
pub const HMAC_KEY_LEN: usize = 32;

/// One-time salt generation.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generic Argon2 derivation into provided buffer of any length.
fn derive_key_raw(password: &str, salt: &[u8], out: &mut [u8]) -> Result<()> {
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, out)
        .map_err(|e| anyhow!("Key derivation failed: {e}"))
}

/// Derive a 256-bit key from a password and salt using Argon2.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    derive_key_raw(password, salt, &mut *key)?;
    Ok(key)
}

/// Derive both the encryption key and HMAC key from a single Argon2 pass (Instead of 2 argon2 passes)
/// then split via HKDF-SHA256 with distinct context labels so the two stays unique
pub fn derive_keys(
    password: &str,
    salt: &[u8],
) -> Result<(Zeroizing<[u8; KEY_LEN]>, Zeroizing<[u8; HMAC_KEY_LEN]>)> {
    let master = derive_key(password, salt)?;

    let hk = Hkdf::<Sha256>::new(None, &*master);

    let mut enc_key = Zeroizing::new([0u8; KEY_LEN]);
    let mut hmac_key = Zeroizing::new([0u8; HMAC_KEY_LEN]);

    hk.expand(b"envseal-enc", &mut *enc_key)
        .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;
    hk.expand(b"envseal-hmac", &mut *hmac_key)
        .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;

    Ok((enc_key, hmac_key))
}

pub fn compute_hmac(key: &[u8; HMAC_KEY_LEN], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn verify_hmac(key: &[u8; HMAC_KEY_LEN], data: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(tag).is_ok() // constant-time
}

/// Encrypt `plaintext` with a freshly generated random nonce.
/// Returns `(nonce, ciphertext)`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt `ciphertext` using `key` and `nonce_bytes`.
pub fn decrypt(key: &[u8; KEY_LEN], nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm::new(key.into());
    if nonce_bytes.len() != NONCE_LEN {
        return Err(anyhow!("Invalid nonce length: corrupted data!!!"));
    }
    let nonce = Nonce::try_from(nonce_bytes)?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed: wrong password or corrupted data!!!"))?;
    String::from_utf8(plaintext).map_err(|e| anyhow!("Decrypted data was not valid utf8: {e}"))
}

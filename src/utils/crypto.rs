use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;

pub const ARGON2_M_COST: u32 = 65536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;

/// One-time salt generation.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Runs argon2 to output a variable output length
fn run_argon2(password: &str, salt: &[u8], out_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    if out_len == 0 {
        return Err(anyhow!("Argon2 output length must be greater than zero!!"));
    }

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(out_len))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = Zeroizing::new(vec![0u8; out_len]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut hash)
        .map_err(|e| anyhow!("Failed to hash password: {e}"))?;
    Ok(hash)
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let derived = run_argon2(password, salt, KEY_LEN)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(derived.as_ref());
    Ok(key)
}

pub fn derive_master_keys(
    password: &str,
    salt: &[u8],
) -> Result<(Zeroizing<[u8; KEY_LEN]>, SigningKey)> {
    let derived = run_argon2(password, salt, 64)?;
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    kek.copy_from_slice(&derived[0..32]);

    let mut seed = Zeroizing::new([0u8; KEY_LEN]);
    seed.copy_from_slice(&derived[32..64]);

    let signing_key = SigningKey::from_bytes(&seed);
    Ok((kek, signing_key))
}

pub fn derive_scope_dek(
    master_dek: &[u8; KEY_LEN],
    group: &str,
    tag: &str,
) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::from_prk(master_dek).expect("PRK length is 32 bytes");
    let mut scope_dek = Zeroizing::new([0u8; KEY_LEN]);
    let info = format!("scope_{}:{}_{}:{}", group.len(), group, tag.len(), tag);
    hk.expand(info.as_bytes(), scope_dek.as_mut())
        .expect("HKDF expansion should not fail for 32 bytes");
    scope_dek
}

pub fn derive_entry_key(scope_dek: &[u8; KEY_LEN], entry_name: &str) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::from_prk(scope_dek).expect("PRK length is 32 bytes");
    let mut entry_key = Zeroizing::new([0u8; KEY_LEN]);
    let scope = format!("var_{entry_name}");
    hk.expand(scope.as_bytes(), entry_key.as_mut())
        .expect("HKDF expansion should not fail for 32 bytes");
    entry_key
}

/// Generates a purely random 32-byte DEK
pub fn generate_dek() -> Zeroizing<[u8; KEY_LEN]> {
    let mut dek = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut dek);
    Zeroizing::new(dek)
}

/// Encrpts the plaintext bytes
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| anyhow!("Invalid nonce length"))?;

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow!("Encryption failed!!"))?;

    Ok((nonce_bytes, ciphertext))
}

/// decrypts the cipher text and returns plaintext as bytes
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::try_from(nonce).map_err(|_| anyhow!("Invalid nonce length"))?;

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed!!"))
}

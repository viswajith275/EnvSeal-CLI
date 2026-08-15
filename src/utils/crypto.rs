use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
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

    let params = Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(out_len),
    )
    .map_err(|e| anyhow!("Invalid Argon2 parameters: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut hash = Zeroizing::new(vec![0u8; out_len]);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut hash)
        .map_err(|e| anyhow!("Failed to hash password: {e}"))?;

    Ok(hash)
}

/// Derives a standard 32-byte key (Used for Tag KEKs)
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let derived = run_argon2(password, salt, KEY_LEN)?;
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(derived.as_ref());

    Ok(Zeroizing::new(key))
}

/// Derives master_kek and signing_key from master_password or tag_password
pub fn derive_master_keys(
    password: &str,
    salt: &[u8],
) -> Result<(Zeroizing<[u8; KEY_LEN]>, SigningKey)> {
    let derived = run_argon2(password, salt, 64)?;
    let mut kek = [0u8; KEY_LEN];
    kek.copy_from_slice(&derived[0..32]);

    let mut seed = [0u8; KEY_LEN];
    seed.copy_from_slice(&derived[32..64]);

    Ok((Zeroizing::new(kek), SigningKey::from_bytes(&seed)))
}

/// Derives an isolated Scope DEK from the Master DEK using the group and tag as context (for seperating the token from accessing out of scope items)
pub fn derive_scope_dek(master_dek: &[u8; KEY_LEN], group: &str, tag: &str) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, master_dek);
    let mut scope_dek = [0u8; KEY_LEN];

    let info = format!("scope_{group}_{tag}");
    hk.expand(info.as_bytes(), &mut scope_dek)
        .expect("HKDF expansion should never fail for 32 bytes!!");

    scope_dek
}

/// Derives a mathematically isolated 32-byte key for a specific environment variable
pub fn derive_entry_key(scope_dek: &[u8; KEY_LEN], entry_name: &str) -> [u8; KEY_LEN] {
    // Initial Keying Material ()
    let hk = Hkdf::<Sha256>::new(None, scope_dek);
    let mut entry_key = [0u8; KEY_LEN];

    let scope = format!("var_{}", entry_name);
    // Expand it into a unique key using the variable name as the contextual info
    hk.expand(scope.as_bytes(), &mut entry_key)
        .expect("HKDF expansion should never fail for 32 bytes!!");

    entry_key
}

/// Generates a purely random 32-byte DEK
pub fn generate_dek() -> Zeroizing<[u8; KEY_LEN]> {
    let mut dek = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut dek);
    Zeroizing::new(dek)
}

/// Encrpts the plaintext bytes
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new((key).into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce_bytes.into(), plaintext)
        .map_err(|_| anyhow!("Encryption failed!!"))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// decrypts the cipher text and returns plaintext as bytes
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());

    let nonce_arr: &[u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| anyhow!("Invalid nonce length!!"))?;

    cipher
        .decrypt(nonce_arr.into(), ciphertext)
        .map_err(|_| anyhow!("Decryption failed!!"))
}

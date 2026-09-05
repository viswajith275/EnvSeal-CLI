use crate::utils::{
    crypto,
    session::{CachedKeys, SessionManager},
    vault::{Vault, VaultKeys},
};
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

pub fn sudo_unlock(vault: &Vault, label: Option<&str>, allow_env: bool) -> Result<VaultKeys> {
    let scope = vault.master_scope();

    if let Ok(Some(CachedKeys::Master { dek, seed })) = SessionManager::get_active_keys(&scope) {
        return Ok(VaultKeys {
            master_kek: Zeroizing::new([0u8; crypto::KEY_LEN]),
            master_dek: Zeroizing::new(dek),
            signing_key: SigningKey::from_bytes(&seed),
        });
    }

    let keys = vault.unlock(allow_env).with_context(|| match label {
        Some(l) => format!("Failed to unlock vault for '{l}' !!"),
        None => "Failed to unlock vault!!".to_string(),
    })?;

    let _ = SessionManager::cache_keys(
        &scope,
        CachedKeys::Master {
            dek: *keys.master_dek,
            seed: keys.signing_key.to_bytes(),
        },
    );

    Ok(keys)
}

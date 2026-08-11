use crate::utils::{
    crypto,
    session::{CachedKeys, SessionManager},
    vault::{Vault, VaultKeys},
};
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use std::env;
use zeroize::Zeroizing;

/// Unlocks the master vault, utilizing cached cryptographic keys if available
pub fn sudo_unlock(vault: &Vault) -> Result<VaultKeys> {
    let scope = vault.master_scope();

    if let Some(cached_keys) = SessionManager::get_active_keys(&scope)? {
        if let CachedKeys::Master { kek, seed } = cached_keys {
            let signing_key = SigningKey::from_bytes(&seed);

            if let Ok(master_dek_bytes) = crypto::decrypt(
                &kek,
                &vault.wrapped_master_dek.nonce,
                &vault.wrapped_master_dek.ciphertext,
            ) {
                let mut master_dek = [0u8; crypto::KEY_LEN];
                master_dek.copy_from_slice(&master_dek_bytes);

                return Ok(VaultKeys {
                    master_kek: Zeroizing::new(kek),
                    master_dek: Zeroizing::new(master_dek),
                    signing_key,
                });
            } else {
                let _ = SessionManager::clear_session(&scope);
            }
        }
    }

    let password = if let Ok(env_pass) = env::var("ENVSEAL_PASSWORD") {
        if !env_pass.is_empty() {
            Zeroizing::new(env_pass)
        } else {
            Zeroizing::new(rpassword::prompt_password(
                "[sudo] master password for envseal: ",
            )?)
        }
    } else {
        Zeroizing::new(rpassword::prompt_password(
            "[sudo] master password for envseal: ",
        )?)
    };

    let keys = vault.unlock(password.as_str())?;

    let mut kek = [0u8; crypto::KEY_LEN];
    kek.copy_from_slice(&*keys.master_kek);

    let mut seed = [0u8; crypto::KEY_LEN];
    seed.copy_from_slice(keys.signing_key.to_bytes().as_slice());

    SessionManager::cache_keys(&scope, CachedKeys::Master { kek, seed })?;

    Ok(keys)
}

/// Unlocks a protected tag and returns its isolated Tag DEK
pub fn sudo_unlock_tag(
    vault: &Vault,
    group: Option<&str>,
    tag: &str,
) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>> {
    let group_name = vault.resolve_group_name(group)?;
    let scope = vault.tag_scope(group, tag)?;

    if let Some(cached_keys) = SessionManager::get_active_keys(&scope)? {
        if let CachedKeys::Tag { dek } = cached_keys {
            return Ok(Zeroizing::new(dek));
        } else {
            let _ = SessionManager::clear_session(&scope);
        }
    }

    let env_tag_var = format!(
        "ENVSEAL_TAG_PASSWORD_{}",
        tag.to_uppercase().replace('-', "_")
    );

    let tag_password =
        if let Ok(pass) = env::var(&env_tag_var).or_else(|_| env::var("ENVSEAL_TAG_PASSWORD")) {
            if !pass.is_empty() {
                Zeroizing::new(pass)
            } else {
                Zeroizing::new(rpassword::prompt_password(format!(
                    "[sudo] password for tag '{tag}' in group '{group_name}': "
                ))?)
            }
        } else {
            Zeroizing::new(rpassword::prompt_password(format!(
                "[sudo] password for tag '{tag}' in group '{group_name}': "
            ))?)
        };

    let tag_dek = vault
        .unlock_tag(group, tag, &tag_password)
        .map_err(|_| anyhow!("Authentication failed for tag '{tag}'!"))?;

    let mut dek = [0u8; crypto::KEY_LEN];
    dek.copy_from_slice(&*tag_dek);

    SessionManager::cache_keys(&scope, CachedKeys::Tag { dek })?;

    Ok(tag_dek)
}

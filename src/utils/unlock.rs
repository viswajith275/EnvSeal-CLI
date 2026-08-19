use crate::utils::{
    crypto,
    session::{CachedKeys, SessionManager},
    vault::{Vault, VaultKeys},
};
use anyhow::Result;
use ed25519_dalek::SigningKey;
use std::env;
use zeroize::Zeroizing;

/// Unlocks the master vault, utilizing cached cryptographic keys if available
pub fn sudo_unlock(vault: &Vault, label: Option<&str>, allow_env: bool) -> Result<VaultKeys> {
    let scope = vault.master_scope();

    if let Some(CachedKeys::Master { kek, seed }) = SessionManager::get_active_keys(&scope)? {
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

    let prompt = match label {
        Some(l) => format!("[sudo] master password for envseal ({l}): "),
        None => "[sudo] master password for envseal: ".to_string(),
    };

    let password = if allow_env {
        if let Ok(env_pass) = env::var("ENVSEAL_PASSWORD") {
            if !env_pass.is_empty() {
                Zeroizing::new(env_pass)
            } else {
                // if allow env and not env_pass
                Zeroizing::new(rpassword::prompt_password(prompt)?)
            }
        } else {
            // not env pass
            Zeroizing::new(rpassword::prompt_password(prompt)?)
        }
    } else {
        // if not allow env
        Zeroizing::new(rpassword::prompt_password(prompt)?)
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
    label: Option<&str>,
    allow_env: bool,
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

    let prompt = match label {
        Some(l) => format!("[sudo] password for tag '{tag}' in group '{group_name}' ({l}): "),
        None => format!("[sudo] password for tag '{tag}' in group '{group_name}': "),
    };

    let tag_password = if allow_env {
        let env_tag_var = format!(
            "ENVSEAL_TAG_PASSWORD_{}",
            tag.to_uppercase().replace('-', "_")
        );
        if let Ok(pass) = env::var(&env_tag_var).or_else(|_| env::var("ENVSEAL_TAG_PASSWORD")) {
            if !pass.is_empty() {
                Zeroizing::new(pass)
            } else {
                Zeroizing::new(rpassword::prompt_password(prompt)?)
            }
        } else {
            Zeroizing::new(rpassword::prompt_password(prompt)?)
        }
    } else {
        Zeroizing::new(rpassword::prompt_password(prompt)?)
    };

    let tag_dek = vault.unlock_tag(group, tag, &tag_password)?;

    let mut dek = [0u8; crypto::KEY_LEN];
    dek.copy_from_slice(&*tag_dek);

    SessionManager::cache_keys(&scope, CachedKeys::Tag { dek })?;

    Ok(tag_dek)
}

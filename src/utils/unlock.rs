use crate::utils::crypto::KEY_LEN;
use crate::utils::session::SessionManager;
use crate::utils::vault::{Vault, VaultKeys};
use anyhow::{anyhow, Result};
use std::env;
use zeroize::Zeroizing;

/// unlock master password
pub fn sudo_unlock(vault: &Vault) -> Result<VaultKeys> {
    let scope = vault.master_scope();
    if let Some(password) = SessionManager::get_active_password(&scope)? {
        if let Ok(keys) = vault.unlock(&password) {
            SessionManager::cache_password(&scope, &password)?;
            return Ok(keys);
        } else {
            SessionManager::clear_session(&scope)?;
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

    SessionManager::cache_password(&scope, password.as_str())?;

    Ok(keys)
}

/// unlock protected tag
pub fn sudo_unlock_tag(
    vault: &Vault,
    group: Option<&str>,
    tag: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let group_name = vault.resolve_group_name(group)?;

    let scope = vault.tag_scope(group, tag)?;

    if let Some(pw) = SessionManager::get_active_password(&scope)? {
        if let Ok(tag_key) = vault.unlock_tag(group, tag, &pw) {
            SessionManager::cache_password(&scope, &pw)?;
            return Ok(tag_key);
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
                    "[sudo] password for tag '{}' in group '{}': ",
                    tag, group_name
                ))?)
            }
        } else {
            Zeroizing::new(rpassword::prompt_password(format!(
                "[sudo] password for tag '{}' in group '{}': ",
                tag, group_name
            ))?)
        };

    let tag_key = vault
        .unlock_tag(group, tag, &tag_password)
        .map_err(|_| anyhow!("Authentication failed for tag '{tag}'!"))?;

    SessionManager::cache_password(&scope, &tag_password)?;

    Ok(tag_key)
}

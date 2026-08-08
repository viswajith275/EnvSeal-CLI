use crate::utils::crypto::KEY_LEN;
use crate::utils::session::SessionManager;
use crate::utils::vault::{Vault, VaultKeys};
use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

pub const MASTER_SCOPE: &str = "master";

/// unlock master password
pub fn sudo_unlock(vault: &Vault) -> Result<VaultKeys> {
    if let Some(password) = SessionManager::get_active_password(MASTER_SCOPE)? {
        if let Ok(keys) = vault.unlock(&password) {
            SessionManager::cache_password(MASTER_SCOPE, &password)?;
            return Ok(keys);
        } else {
            SessionManager::clear_session(MASTER_SCOPE)?;
        }
    }

    let password = Zeroizing::new(rpassword::prompt_password(
        "[sudo] master password for envseal: ",
    )?);

    let keys = vault.unlock(password.as_str())?;

    SessionManager::cache_password(MASTER_SCOPE, password.as_str())?;

    Ok(keys)
}

/// unlock protected tag
pub fn sudo_unlock_tag(
    vault: &Vault,
    group: Option<&str>,
    tag: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let group_name = vault.resolve_group_name(group)?;

    let scope = format!("group_{}_tag_{}", group_name, tag);

    if let Some(pw) = SessionManager::get_active_password(&scope)? {
        if let Ok(tag_key) = vault.unlock_tag(group, tag, &pw) {
            SessionManager::cache_password(&scope, &pw)?;
            return Ok(tag_key);
        } else {
            let _ = SessionManager::clear_session(&scope);
        }
    }

    let tag_password = Zeroizing::new(rpassword::prompt_password(format!(
        "[sudo] password for tag '{}' in group '{}': ",
        tag, group_name
    ))?);

    let tag_key = vault
        .unlock_tag(group, tag, &tag_password)
        .map_err(|_| anyhow!("Authentication failed for tag '{tag}'!"))?;

    SessionManager::cache_password(&scope, &tag_password)?;

    Ok(tag_key)
}

use crate::utils::{session::SessionManager, unlock, vault::Vault};
use anyhow::Result;

pub fn cmd_rotate(global: bool, pref: Option<&str>, allow_env: bool) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, None, allow_env)?;

    eprintln!("re-encrypting vault and rotating DEK...");

    let old_scope = vault.master_scope();
    vault.rotate_dek(&master_keys)?;
    vault.save()?;

    let _ = SessionManager::clear_session(&old_scope);
    let _ = SessionManager::clear_session(&vault.legacy_master_scope());
    eprintln!("successfully rotated DEK. All previous tokens are now invalid.");
    Ok(())
}

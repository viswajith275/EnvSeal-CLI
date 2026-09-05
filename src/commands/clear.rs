use crate::utils::{session::SessionManager, vault::Vault};
use anyhow::Result;

pub fn cmd_clear(global: bool, pref: Option<&str>) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    SessionManager::clear_session(&vault.master_scope())?;
    let location = if vault.is_local() { "local" } else { "global" };
    let env_suffix = pref
        .map(|p| format!(" [profile: .{p}.envseal]"))
        .unwrap_or_default();
    eprintln!("cleared session cache for {location} vault{env_suffix}.");
    Ok(())
}

use crate::utils::{unlock, vault::Vault};
use anyhow::Result;
use std::env;

pub fn cmd_link(group: &str, global: bool, pref: Option<&str>, allow_env: bool) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, None, allow_env)?;

    vault.link_group(&master_keys.signing_key, group)?;
    vault.save()?;

    let current_dir = env::current_dir()?;
    eprintln!(
        "linked group '{group}' to directory '{}'",
        current_dir.display()
    );

    Ok(())
}

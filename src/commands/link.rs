use crate::utils::{unlock, vault::Vault};
use anyhow::Result;
use std::env;

pub fn cmd_link(group: &str, _global: bool, pref: Option<&str>, allow_env: bool) -> Result<()> {
    let mut vault = Vault::load(true, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, Some("link"), allow_env)?;

    vault.link_group(&master_keys.signing_key, group)?;
    vault.save()?;

    let current_dir = env::current_dir()?;
    eprintln!(
        "linked group '{group}' to directory '{}'",
        current_dir.display()
    );

    Ok(())
}

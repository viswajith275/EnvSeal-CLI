use crate::utils::{unlock, vault::Vault};
use anyhow::Result;
use std::env;

pub fn cmd_link(group: &str, global: bool, pref: Option<&str>) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;
    let derived = unlock::sudo_unlock(&vault)?;

    vault.link_group(&derived.hmac_key, group)?;
    vault.save()?;

    let current_dir = env::current_dir()?;
    eprintln!(
        "linked group '{group}' to directory '{}'",
        current_dir.display()
    );

    Ok(())
}

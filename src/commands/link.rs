use crate::utils::{unlock, vault::Vault};
use anyhow::Result;

pub fn cmd_link(group: &str) -> Result<()> {
    let mut vault = Vault::load()?;
    let derived = unlock::sudo_unlock(&vault)?;

    vault.link_group(&derived.hmac_key, group)?;
    vault.save()?;

    Ok(())
}

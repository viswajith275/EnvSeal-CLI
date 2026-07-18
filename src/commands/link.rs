use crate::utils::vault::Vault;
use anyhow::{Ok, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_link(group: String) -> Result<()> {
    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let _ = vault.unlock(&password)?;

    vault.link_group(group)?;
    vault.save()?;

    Ok(())
}

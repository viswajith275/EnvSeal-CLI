use crate::utils::vault::Vault;
use anyhow::{Context, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_get(key: &str, group_name: &str) -> Result<()> {
    let vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let value = vault
        .get_entry(&derived, group_name, key)
        .with_context(|| format!("failed to read '{key}'"))?;

    println!("{value}");
    Ok(())
}

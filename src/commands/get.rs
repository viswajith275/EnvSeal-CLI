use crate::utils::vault::Vault;
use zeroize::Zeroizing;
use rpassword::prompt_password;
use anyhow::{Context, Result};

pub fn cmd_get(key: &str) -> Result<()> {
    let vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;
 
    let value = vault.get_entry(&derived, key).with_context(|| format!("failed to read '{key}'"))?;

    println!("{value}");
    Ok(())
}
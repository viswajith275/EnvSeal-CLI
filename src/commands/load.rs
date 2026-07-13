use crate::utils::vault::Vault;
use zeroize::Zeroizing;
use rpassword::prompt_password;
use anyhow::{Context, Result};

pub fn cmd_load(keys: &[String]) -> Result<()> {
    let vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;
    
    eprintln!("Loading environment variables...");
    for key in keys {
        let value = vault.get_entry(&derived, key).with_context(|| format!("failed to read '{key}'"))?;
        println!("export {key}={value}");
    }
    Ok(())
}
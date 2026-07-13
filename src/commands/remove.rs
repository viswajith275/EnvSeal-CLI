use crate::utils::vault::Vault;
use zeroize::Zeroizing;
use rpassword::prompt_password;
use anyhow::Result;

pub fn cmd_remove(key: &str) -> Result<()> {

    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let _ = vault.unlock(&password)?;
 
    vault.remove_entry(key)?;
    vault.save()?;
 
    eprintln!("Removed {key}");
    Ok(())
}
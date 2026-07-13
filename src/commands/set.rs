use crate::utils::vault::Vault;
use zeroize::Zeroizing;
use rpassword::prompt_password;
use anyhow::Result;

pub fn cmd_set(key: &str) -> Result<()> {
    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;
 
    let secret = Zeroizing::new(prompt_password(&format!("Value for {key}: "))?);
    vault.add_entry(&derived, key, &secret)?;
    vault.save()?;
 
    eprintln!("Stored {key}");
    Ok(())
}
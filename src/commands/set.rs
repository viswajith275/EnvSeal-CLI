use crate::utils::vault::Vault;
use anyhow::Result;
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_set(key: &str, group_name: &str) -> Result<()> {
    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let secret = Zeroizing::new(prompt_password(&format!("Value for {key}: "))?);
    vault.add_entry(&derived, group_name, key, &secret)?;
    vault.save()?;

    eprintln!("Stored {key} in group '{group_name}'");
    Ok(())
}

use crate::utils::vault::Vault;
use anyhow::Result;
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_set(group: &Option<String>, tag: &Option<String>, key: &str) -> Result<()> {
    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let secret = Zeroizing::new(prompt_password(&format!("Value for {key}: "))?);
    vault.set_entry(&derived, group, tag, key, &secret)?;
    vault.save()?;

    eprintln!("Stored {key} inside group");
    Ok(())
}

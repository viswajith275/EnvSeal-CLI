use crate::utils::vault::Vault;
use anyhow::Result;
use dialoguer::Confirm;
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_remove(key: &Option<String>, group_name: &str) -> Result<()> {
    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let _ = vault.unlock(&password)?;

    if !key.is_none() {
        let key = key.as_ref().unwrap();
        let prompt = format!("Are you sure you want to delete key '{key}'?");

        let confirmation = Confirm::new()
            .with_prompt(prompt)
            .default(false)
            .interact()
            .unwrap();
        if confirmation {
            vault.remove_entry(group_name, key)?;
            vault.save()?;
            eprintln!("Removed '{key}' from group '{group_name}'");
        } else {
            eprintln!("Operation canceled by user!");
        }

        Ok(())
    } else {
        let prompt = format!("Are you sure you want to delete group '{group_name}'?");

        let confirmation = Confirm::new()
            .with_prompt(prompt)
            .default(false)
            .interact()
            .unwrap();

        if confirmation {
            vault.remove_group(group_name)?;
            vault.save()?;
            eprintln!("Removed group '{group_name}'");
        } else {
            eprintln!("Operation canceled by user!");
        }

        Ok(())
    }
}

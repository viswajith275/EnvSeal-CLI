use crate::utils::vault::Vault;
use anyhow::Result;
use dialoguer::Confirm;
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_remove(
    group: &Option<String>,
    tag: &Option<String>,
    key: &Option<String>,
) -> Result<()> {
    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let _ = vault.unlock(&password)?;

    let prompt = format!("Are you sure you want to delete these variables?");

    let confirmation = Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .unwrap();
    if confirmation {
        vault.remove_entry(group, tag, key)?;
        vault.save()?;
        eprintln!("Deletion successful!");
    } else {
        eprintln!("Operation canceled by user!");
    }

    Ok(())
}

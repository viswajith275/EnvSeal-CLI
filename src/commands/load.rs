use crate::utils::vault::Vault;
use anyhow::{Context, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_load(keys: &[String], group_name: &str) -> Result<()> {
    let vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    if !keys.is_empty() {
        eprintln!("loading selected environment variables from {group_name}...");
        for key in keys {
            let value = vault
                .get_entry(&derived, group_name, key)
                .with_context(|| format!("failed to read '{key}'"))?;
            println!("export {key}={value}");
        }
    } else {
        eprintln!("loading all environment variables from {group_name}...");
        let keys = match vault.list_all_keys(group_name) {
            Ok(value) => value,
            Err(_) => panic!("no group named {group_name}"),
        };
        for key in keys {
            let value = vault
                .get_entry(&derived, group_name, &key)
                .with_context(|| format!("failed to read '{key}'"))?;
            println!("export {key}={value}");
        }
    }
    Ok(())
}

use crate::utils::vault::Vault;
use anyhow::{Context, Result};
use dotenvy::from_path_iter;
use rpassword::prompt_password;
use std::path::Path;
use zeroize::Zeroizing;

pub fn cmd_import(group: &Option<String>, tag: &Option<String>, path: &str) -> Result<()> {
    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let path = Path::new(path);

    let iter = from_path_iter(path)
        .with_context(|| format!("Failed to load env file: {}", path.display()))?;

    for item in iter {
        match item {
            Ok((key, value)) => {
                vault.set_entry(&derived, group, tag, &key, &value)?;
            }
            Err(e) => {
                eprintln!("Warniing: Failed to parse line: {}", e);
            }
        }
    }

    vault.save()?;

    eprintln!("Stored env variables in group!");
    Ok(())
}

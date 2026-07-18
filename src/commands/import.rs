use crate::utils::vault::Vault;
use anyhow::Result;
use dotenvy::from_path_iter;
use rpassword::prompt_password;
use std::path::Path;
use zeroize::Zeroizing;

pub fn cmd_import(group_name: &str, path: &str) -> Result<()> {
    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let path = Path::new(path);

    match from_path_iter(path) {
        Ok(iter) => {
            for item in iter {
                match item {
                    Ok((key, value)) => {
                        vault.add_entry(&derived, group_name, &key, &value)?;
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to parse a line: {}", e);
                    }
                }
            }
        }
        Err(error) => panic!("Failed to load env variables!: {error}"),
    }

    vault.save()?;

    eprintln!("Stored env variables in group '{group_name}'");
    Ok(())
}

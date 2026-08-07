use crate::utils::vault::Vault;
use anyhow::{Context, Result};
use dotenvy::from_path_iter;
use rpassword::prompt_password;
use std::path::Path;
use zeroize::Zeroizing;

pub fn cmd_import(group: Option<&str>, tag: Option<&str>, path: &str) -> Result<()> {
    let mut vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let path = Path::new(path);

    let iter = from_path_iter(path)
        .with_context(|| format!("Failed to load env file: {}", path.display()))?;

    let mut tag_password: Option<Zeroizing<String>> = None;

    if vault.is_tag_protected(group, tag)? {
        tag_password = Some(Zeroizing::new(prompt_password("Tag Password: ")?));
    }

    for item in iter {
        match item {
            Ok((key, value)) => {
                vault.set_entry(
                    &derived,
                    group,
                    tag,
                    &key,
                    &value,
                    tag_password.as_ref().map(|s| s.as_str()),
                )?;
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

use std::collections::HashMap;

use crate::utils::vault::Vault;
use anyhow::{Context, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_export(group: &Option<String>, tag: &Option<String>, keys: &[String]) -> Result<()> {
    let vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let mut merged_env: HashMap<String, String> = HashMap::new();

    if !keys.is_empty() {
        eprintln!("loading selected environment variables...");
        for key in keys {
            let value = if tag.is_some() {
                match vault.get_entry(&derived, group, tag, &key) {
                    Ok(val) => val,
                    Err(_) => vault
                        .get_entry(&derived, group, &None, &key)
                        .with_context(|| {
                            format!("failed to read '{key}' from tag or base group")
                        })?,
                }
            } else {
                vault
                    .get_entry(&derived, group, &None, &key)
                    .with_context(|| format!("failed to read '{key}'"))?
            };

            merged_env.insert(key.to_string(), value);
        }
    } else {
        eprintln!("loading all environment variables...");
        let group_keys = vault.list_all_keys(group, &None)?;
        for key in group_keys {
            let value = vault
                .get_entry(&derived, group, &None, &key)
                .with_context(|| format!("failed to read base key '{key}'"))?;
            merged_env.insert(key, value);
        }

        if tag.is_some() {
            let tag_keys = vault.list_all_keys(group, tag)?;
            for key in tag_keys {
                let value = vault
                    .get_entry(&derived, group, tag, &key)
                    .with_context(|| format!("failed to read tag key '{key}'"))?;
                merged_env.insert(key, value);
            }
        }
    }

    for (key, value) in merged_env {
        println!("{key}={value}");
    }

    Ok(())
}

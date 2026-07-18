use crate::utils::vault::Vault;
use anyhow::{Ok, Result};
use std::collections::HashSet;

pub fn cmd_list(group: &Option<String>, tag: &Option<String>) -> Result<()> {
    let vault = Vault::load()?;

    let group_keys = vault.list_all_keys(group, &None)?;
    let tag_keys = vault.list_all_keys(group, tag)?;

    let mut unique_keys: HashSet<String> = HashSet::new();

    unique_keys.extend(group_keys.clone());
    unique_keys.extend(tag_keys.clone());

    eprintln!("\nStored-Keys");
    eprintln!("--------------------");
    for key in &unique_keys {
        eprintln!("{key}");
    }

    Ok(())
}

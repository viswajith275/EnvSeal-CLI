use crate::utils::vault::Vault;
use anyhow::{Ok, Result};
use std::collections::HashSet;

pub fn cmd_list(group: Option<&str>, tag: Option<&str>) -> Result<()> {
    let vault = Vault::load()?;
    let group_name = vault.resolve_group_name(group)?;
    let group_keys = vault.list_all_keys(group, None)?;
    let tag_keys = vault.list_all_keys(group, tag)?;

    let mut unique_keys: HashSet<String> = HashSet::new();

    unique_keys.extend(group_keys.clone());
    unique_keys.extend(tag_keys.clone());

    let message = if tag.is_some() {
        format!(
            "stored-keys (group: {}) (tag: {})",
            group_name,
            tag.unwrap()
        )
    } else {
        format!("stored-keys (group: {})", group_name)
    };
    eprintln!("{}", message);
    eprintln!("--------------------");
    for key in &unique_keys {
        eprintln!("{key}");
    }

    Ok(())
}

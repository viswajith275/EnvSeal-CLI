use crate::utils::vault::Vault;
use anyhow::Result;
use std::collections::BTreeSet;

pub fn cmd_list(group: Option<&str>, tag: Option<&str>, global: bool) -> Result<()> {
    let vault = Vault::load(global)?;
    let group_name = vault.resolve_group_name(group)?;

    let group_keys = vault.list_all_keys(group, None)?;
    let mut unique_keys: BTreeSet<String> = group_keys.into_iter().collect();

    if let Some(t) = tag {
        let tag_keys = vault.list_all_keys(group, Some(t))?;
        unique_keys.extend(tag_keys);
    }

    let location = if vault.is_local() { "local" } else { "global" };
    let header = match tag {
        Some(t) => format!("stored-keys (group: {group_name}) (tag: {t}) [{location}]"),
        None => format!("stored-keys (group: {group_name}) [{location}]"),
    };

    eprintln!("{header}");
    eprintln!("--------------------");

    // 5. Output sorted keys or empty state
    if unique_keys.is_empty() {
        eprintln!("(no keys found)");
    } else {
        for key in &unique_keys {
            eprintln!("{key}");
        }
    }

    Ok(())
}

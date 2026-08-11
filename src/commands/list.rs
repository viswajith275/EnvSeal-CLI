use crate::utils::vault::Vault;
use anyhow::Result;
use std::collections::BTreeSet;

pub fn cmd_list(
    group: Option<&str>,
    tag: Option<&str>,
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let group_name = vault.resolve_group_name(group)?;

    let unique_keys: BTreeSet<String> = vault.list_all_keys(group, tag)?.into_iter().collect();

    let location = if vault.is_local() { "local" } else { "global" };
    let header = match tag {
        Some(t) => format!("stored-keys (group: {group_name}) (tag: {t}) [{location}]"),
        None => format!("stored-keys (group: {group_name}) [{location}]"),
    };

    eprintln!("{header}");
    eprintln!("--------------------");

    if unique_keys.is_empty() {
        eprintln!("(no keys found)");
    } else {
        for key in &unique_keys {
            eprintln!("{key}");
        }
    }

    Ok(())
}

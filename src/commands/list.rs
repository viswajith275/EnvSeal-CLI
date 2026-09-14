use crate::utils::vault::Vault;
use anyhow::Result;
use std::collections::BTreeSet;
use std::io::{stdout, IsTerminal};

pub fn cmd_list(
    group: Option<&str>,
    tag: Option<&str>,
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let group_name = vault.resolve_group_name(group)?;

    let unique_keys: BTreeSet<String> = vault.list_all_keys(group, tag)?.into_iter().collect();

    // Only show human-readable header when attached to an interactive terminal
    if stdout().is_terminal() {
        let location = if vault.is_local() { "local" } else { "global" };
        let header = match tag {
            Some(t) => format!("# group: {group_name}, tag: {t} [{location}]"),
            None => format!("# group: {group_name} [{location}]"),
        };
        eprintln!("{header}");
    }

    for key in &unique_keys {
        println!("{key}");
    }
    Ok(())
}

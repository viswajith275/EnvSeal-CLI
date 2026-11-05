use crate::utils::{resolve, unlock, vault::Vault};
use anyhow::Result;
use std::io::{stdin, stdout};
use std::io::{IsTerminal, Write};

pub fn cmd_remove(
    group: Option<&str>,
    tag: Option<&str>,
    key: Option<&str>,
    global: bool,
    pref: Option<&str>,
    force: bool,
    allow_env: bool,
) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;

    if key.is_some() && tag.is_none() {
        if let Some(branch) = resolve::auto_tag(&vault, group, None) {
            anyhow::bail!(
                "Current branch '{branch}' has a tag in this vault. Pass '--tag {branch}' or '--tag base' to choose which value to remove."
            );
        }
    }
    let master_keys = unlock::sudo_unlock(&vault, Some("remove"), allow_env)?;

    if !force {
        if stdin().is_terminal() {
            let target = key.unwrap_or(tag.unwrap_or("group"));
            print!("Are you sure you want to remove '{target}'? [y/N]: ");
            stdout().flush()?;

            let mut input = String::new();
            stdin().read_line(&mut input)?;

            if !matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                eprintln!("Aborted by user.");
                return Ok(());
            }
        } else {
            anyhow::bail!("Refusing to delete without --force in non-interactive mode")
        }
    }

    vault.remove_entry(&master_keys.signing_key, group, tag, key)?;
    vault.save()?;
    eprintln!("deletion successful!");

    Ok(())
}

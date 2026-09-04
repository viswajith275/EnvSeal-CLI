use crate::utils::{unlock, vault::Vault};
use anyhow::{anyhow, Result};
use std::io::IsTerminal;

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
    let master_keys = unlock::sudo_unlock(&vault, None, allow_env)?;

    let mut tag_key = None;
    if vault.is_tag_protected(group, tag)? {
        if let Some(t) = tag {
            tag_key = Some(unlock::sudo_unlock_tag(&vault, group, t, None, allow_env)?);
        } else {
            return Err(anyhow!(
                "A tag must be provided if the group's default tag is protected."
            ));
        }
    }

    if !force && std::io::stdin().is_terminal() {
        let target = key.unwrap_or(tag.unwrap_or("group"));
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!("Are you sure you want to remove '{target}'?"))
            .default(false)
            .interact()?;

        if !confirmed {
            println!("Aborted by user");
            return Ok(());
        }
    }

    vault.remove_entry(
        &master_keys.signing_key,
        group,
        tag,
        key,
        tag_key.as_deref(),
    )?;
    vault.save()?;
    eprintln!("deletion successful!!");

    Ok(())
}

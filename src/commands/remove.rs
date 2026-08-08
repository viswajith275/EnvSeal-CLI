use crate::utils::{unlock, vault::Vault};
use anyhow::{anyhow, Result};
use dialoguer::Confirm;

pub fn cmd_remove(
    group: Option<&str>,
    tag: Option<&str>,
    key: Option<&str>,
    global: bool,
) -> Result<()> {
    let mut vault = Vault::load(global)?;
    let derived = unlock::sudo_unlock(&vault)?;

    let mut tag_key = None;
    if vault.is_tag_protected(group, tag)? {
        if let Some(t) = tag {
            tag_key = Some(unlock::sudo_unlock_tag(&vault, group, t)?);
        } else {
            return Err(anyhow!(
                "A tag must be provided if the group's default tag is protected."
            ));
        }
    }

    let prompt = format!("do you want to delete these variables?");

    let confirmation = Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .unwrap();
    if confirmation {
        vault.remove_entry(&derived.hmac_key, group, tag, key, tag_key.as_deref())?;
        vault.save()?;
        eprintln!("deletion successful!!");
    } else {
        eprintln!("operation canceled by user!!");
    }

    Ok(())
}

use crate::utils::{unlock, vault::Vault};
use anyhow::{anyhow, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_set(group: Option<&str>, tag: Option<&str>, key: &str) -> Result<()> {
    let mut vault = Vault::load()?;
    let group_name = vault.resolve_group_name(group)?;
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

    let secret = Zeroizing::new(prompt_password(&format!("value for {key}: "))?);

    vault.set_entry(&derived, group, tag, key, &secret, tag_key.as_deref())?;

    vault.save()?;
    let message = if tag.is_some() {
        format!(
            "sealed '{}' in tag '{}' inside group '{}'",
            key,
            tag.unwrap(),
            group_name
        )
    } else {
        format!("sealed '{}' inside group '{}'", key, group_name)
    };

    eprintln!("{}", message);
    Ok(())
}

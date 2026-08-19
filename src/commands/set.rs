use crate::utils::{unlock, vault::Vault};
use anyhow::{anyhow, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_set(
    group: Option<&str>,
    tag: Option<&str>,
    key: &str,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;

    let group_name = vault.resolve_group_name(group)?;
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

    let secret = Zeroizing::new(prompt_password(format!("value for {key}: "))?);

    vault.set_entry(&master_keys, group, tag, key, &secret, tag_key.as_deref())?;
    vault.save()?;

    let location_label = if vault.is_local() { "local" } else { "global" };
    let message = match tag {
        Some(t) => format!(
            "sealed '{key}' in tag '{t}' inside group '{group_name}' ({location_label} seal)"
        ),
        None => format!("sealed '{key}' inside group '{group_name}' ({location_label} seal)"),
    };

    eprintln!("{message}");
    Ok(())
}

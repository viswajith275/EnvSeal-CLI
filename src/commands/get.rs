use crate::utils::{unlock, vault::Vault};
use anyhow::{anyhow, Context, Ok, Result};

pub fn cmd_get(
    group: Option<&str>,
    tag: Option<&str>,
    key: &str,
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
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

    let value = vault
        .get_entry(&derived.enc_key, group, tag, key, tag_key.as_deref())
        .with_context(|| format!("Failed to read '{key}'"))?;

    println!("{}: {}", key, value.as_str());
    Ok(())
}

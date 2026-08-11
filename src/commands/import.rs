use crate::utils::{unlock, vault::Vault};
use anyhow::{anyhow, Context, Result};
use dotenvy::from_path_iter;
use std::path::Path;

pub fn cmd_import(
    group: Option<&str>,
    tag: Option<&str>,
    path: &str,
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;
    let group_name = vault.resolve_group_name(group)?;
    let master_keys = unlock::sudo_unlock(&vault)?;

    let path = Path::new(path);

    let iter = from_path_iter(path)
        .with_context(|| format!("Failed to load env file: {}", path.display()))?;

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

    for item in iter {
        match item {
            Ok((key, value)) => {
                vault.set_entry(&master_keys, group, tag, &key, &value, tag_key.as_deref())?;
            }
            Err(e) => {
                eprintln!("Warniing: Failed to parse line: {}", e);
            }
        }
    }

    vault.save()?;
    let location_label = if vault.is_local() { "local" } else { "global" };
    let message = if tag.is_some() {
        format!(
            "sealed env in tag '{}' inside group '{}' {} seal",
            tag.unwrap(),
            group_name,
            location_label
        )
    } else {
        format!(
            "sealed env inside group '{}' {} seal",
            group_name, location_label
        )
    };

    eprintln!("{}", message);
    Ok(())
}

use crate::utils::{unlock, vault::Vault};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;

pub fn cmd_load(
    group: Option<&str>,
    tag: Option<&str>,
    keys: &[String],
    global: bool,
) -> Result<()> {
    let vault = Vault::load(global)?;
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
    let mut merged_env: HashMap<String, String> = HashMap::new();

    let location_label = if vault.is_local() { "local" } else { "global" };
    let message = if !keys.is_empty() && tag.is_some() {
        format!(
            "loading envs '{:?}' from tag '{}' inside group '{}' {} seal!",
            keys,
            tag.unwrap(),
            group_name,
            location_label
        )
    } else if tag.is_some() {
        format!(
            "loading envs from tag '{}' inside group '{}' {} seal!",
            tag.unwrap(),
            group_name,
            location_label
        )
    } else {
        format!(
            "loading envs from group '{}' {} seal!",
            group_name, location_label
        )
    };

    eprintln!("{}", message);

    if !keys.is_empty() {
        for key in keys {
            let value = if tag.is_some() {
                match vault.get_entry(&derived.enc_key, group, tag, &key, tag_key.as_deref()) {
                    Ok(val) => val,
                    Err(_) => vault
                        .get_entry(&derived.enc_key, group, None, &key, tag_key.as_deref())
                        .with_context(|| {
                            format!("Failed to read '{}' from tag '{}'", key, tag.unwrap())
                        })?,
                }
            } else {
                vault
                    .get_entry(&derived.enc_key, group, None, &key, tag_key.as_deref())
                    .with_context(|| format!("Failed to read '{}'", key))?
            };

            merged_env.insert(key.to_string(), value.to_string());
        }
    } else {
        let group_keys = vault.list_all_keys(group, None)?;
        for key in group_keys {
            let value = vault
                .get_entry(&derived.enc_key, group, None, &key, tag_key.as_deref())
                .with_context(|| format!("Failed to read base key '{}'", key))?;
            merged_env.insert(key, value.to_string());
        }

        if tag.is_some() {
            let tag_keys = vault.list_all_keys(group, tag)?;
            for key in tag_keys {
                let value = vault
                    .get_entry(&derived.enc_key, group, tag, &key, tag_key.as_deref())
                    .with_context(|| format!("Failed to read tag key '{}'", key))?;
                merged_env.insert(key, value.to_string());
            }
        }
    }

    for (key, value) in merged_env {
        println!("export {key}={value}");
    }

    Ok(())
}

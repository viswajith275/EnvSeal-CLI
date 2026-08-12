use crate::utils::{resolve, vault::Vault};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;

pub fn cmd_export(
    group: Option<&str>,
    tag: Option<&str>,
    keys: Vec<&str>,
    token_file: Option<&PathBuf>,
    global: bool,
    pref: Option<&str>,
    output_path: Option<&str>,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let group_name = vault.resolve_group_name(group)?;

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

    let mut decrypted_envs = resolve::resolve_secrets(&vault, group, tag, token_file)?;

    if !keys.is_empty() {
        let requested_set: HashSet<&str> = keys.iter().copied().collect();
        decrypted_envs.retain(|k, _| requested_set.contains(k.as_str()));

        for key in &keys {
            if !decrypted_envs.contains_key(*key) {
                eprintln!(
                        "Warning: '{}' was not found in the vault, or the provided token lacks permission to decrypt it. Skipping...",
                        key
                    );
            }
        }
    }

    let mut sorted_envs: BTreeMap<String, String> = BTreeMap::new();
    for (key, mut value) in decrypted_envs {
        sorted_envs.insert(key, value.to_string());
        zeroize::Zeroize::zeroize(&mut value);
    }

    let mut buffer = String::new();
    for (key, value) in &sorted_envs {
        buffer.push_str(&format!("{key}={}\n", format_env_value(value.as_str())));
    }

    // Default target file to .env if not specified
    let target_file = output_path.unwrap_or(".env");

    // Write file natively to disk
    fs::write(target_file, buffer).with_context(|| {
        format!("Failed to write exported environment variables to '{target_file}'")
    })?;

    eprintln!(
        "successfully exported {} variable(s) to '{}'",
        sorted_envs.len(),
        target_file
    );

    Ok(())
}

fn format_env_value(value: &str) -> String {
    if value.contains('\n')
        || value.contains(' ')
        || value.contains('"')
        || value.contains('#')
        || value.contains('$')
    {
        format!(
            "\"{}\"",
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
        )
    } else {
        value.to_string()
    }
}

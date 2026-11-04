use crate::utils::is_valid_env_key;
use crate::utils::{unlock, vault::Vault};
use anyhow::Result;
use std::io::{stdin, IsTerminal, Read};
use std::path::Path;
use zeroize::Zeroizing;

const MAX_STDIN_BUF_SIZE: u64 = 64 * 1024;

pub fn cmd_set(
    group: Option<&str>,
    tag: Option<&str>,
    key: &str,
    file: Option<&Path>,
    env_var: Option<&str>,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    if file.is_none() && !is_valid_env_key(key) {
        anyhow::bail!(
            "Invalid environment variable name '{key}'. Keys must start with a letter or underscore and contain only alphanumeric characters and underscores."
        );
    }
    let mut vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, Some("set"), allow_env)?;

    if let Some(file_path) = file {
        let env_name = match env_var {
            Some(e) => e,
            None => key,
        };

        if !is_valid_env_key(env_name) {
            anyhow::bail!("Invalid environment variable name '{env_name}'");
        }

        vault.set_file_entry(&master_keys, group, tag, key, env_name, file_path)?;

        vault.save()?;

        let group_name = vault.resolve_group_name(group)?;
        let location = if vault.is_local() { "local" } else { "global" };
        let scope_label = tag
            .map(|t| format!("tag '{t}' inside "))
            .unwrap_or_default();

        eprintln!("sealed file '{key}' in {scope_label}group '{group_name}' ({location} seal)");

        return Ok(());
    }

    let secret = Zeroizing::new(if stdin().is_terminal() {
        rpassword::prompt_password(format!("value for {key}: "))?
    } else {
        let mut buf = String::new();
        stdin().take(MAX_STDIN_BUF_SIZE + 1).read_to_string(&mut buf)?;
        if buf.len() as u64 > MAX_STDIN_BUF_SIZE {
            anyhow::bail!(
                "Text exceeds the maximum supported size of {} KB",
                MAX_STDIN_BUF_SIZE / 1024
            );
        }
        buf.trim_end_matches(&['\r', '\n'][..]).to_string()
    });
    vault.set_entry(&master_keys, group, tag, key, &secret)?;
    vault.save()?;

    let group_name = vault.resolve_group_name(group)?;
    let location = if vault.is_local() { "local" } else { "global" };
    let scope_label = tag
        .map(|t| format!("tag '{t}' inside "))
        .unwrap_or_default();

    eprintln!("sealed '{key}' in {scope_label}group '{group_name}' ({location} seal)");
    Ok(())
}

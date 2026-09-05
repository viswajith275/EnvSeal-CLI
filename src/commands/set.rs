use crate::utils::is_valid_env_key;
use crate::utils::{unlock, vault::Vault};
use anyhow::Result;

pub fn cmd_set(
    group: Option<&str>,
    tag: Option<&str>,
    key: &str,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    if !is_valid_env_key(key) {
        anyhow::bail!(
            "Invalid environment variable name '{key}'. Keys must start with a letter or underscore and contain only alphanumeric characters and underscores."
        );
    }

    let mut vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, Some("set"), allow_env)?;

    let secret = rpassword::prompt_password(format!("value for {key}: "))?;
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

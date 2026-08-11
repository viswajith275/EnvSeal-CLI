use crate::utils::{resolve, vault::Vault};
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use zeroize::Zeroize;

pub fn cmd_get(
    group: Option<&str>,
    tag: Option<&str>,
    key: &str,
    token_file: Option<&PathBuf>,
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let mut decrypted_envs = resolve::resolve_secrets(&vault, group, tag, token_file)?;

    let mut value = decrypted_envs
        .remove(key)
        .ok_or_else(|| anyhow!("No entry named '{key}' found in the current scope!!"))?;

    println!("{}: {}", key, value.as_str());

    value.zeroize();

    Ok(())
}

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
    allow_env: bool,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let mut decrypted_envs = resolve::resolve_secrets(&vault, group, tag, token_file, allow_env)?;

    if let Some(mut value) = decrypted_envs.remove(key) {
        println!("{}: {}", key, value.as_str());
        Zeroize::zeroize(&mut value);
    } else {
        return Err(anyhow!(
            "No entry named '{key}' found, or the provided token lacks permission to decrypt it!"
        ));
    }

    Ok(())
}

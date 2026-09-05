use crate::utils::{resolve, vault::Vault};
use anyhow::{anyhow, Result};

pub fn cmd_get(
    group: Option<&str>,
    tag: Option<&str>,
    key: &str,
    token: Option<&str>,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let token_str = resolve::load_token(token)?;
    let mut decrypted_envs =
        resolve::resolve_environment(&vault, group, tag, token_str.as_deref(), allow_env)?;

    if let Some(value) = decrypted_envs.remove(key) {
        println!("{}: {}", key, value.as_str());
    } else {
        return Err(anyhow!(
            "No entry named '{key}' found, or the provided token lacks permission to decrypt it!"
        ));
    }

    Ok(())
}

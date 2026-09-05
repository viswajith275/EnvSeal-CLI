use crate::utils::{resolve, vault::Vault};
use anyhow::{Context, Result};
use std::process::Command;

pub fn cmd_run(
    group: Option<&str>,
    tag: Option<&str>,
    token: Option<&str>,
    command: &[String],
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<u8> {
    if command.is_empty() {
        anyhow::bail!("No command specified to run.");
    }

    let token_str = resolve::load_token(token)?;
    let vault = Vault::load(global, pref)?;
    let env_vars =
        resolve::resolve_environment(&vault, group, tag, token_str.as_deref(), allow_env)?;

    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    for (k, v) in env_vars {
        child.env(k, v.as_str());
    }

    let status = child
        .status()
        .with_context(|| format!("Failed to execute command '{}'", &command[0]))?;

    std::process::exit(status.code().unwrap_or(1))
}

use crate::utils::{resolve, vault::Vault};
use anyhow::{Context, Ok, Result};
use std::path::PathBuf;
use std::process::Command;

pub fn cmd_run(
    group: Option<&str>,
    tag: Option<&str>,
    args: Vec<&str>,
    token_file: Option<&PathBuf>,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<i32> {
    let (cmd_name, cmd_args) = args.split_first().context("No command provided to run!!")?;

    let vault = Vault::load(global, pref)?;

    let mut child_cmd = Command::new(cmd_name);
    child_cmd.args(cmd_args);

    for (env_key, _) in std::env::vars() {
        if env_key.starts_with("ENVSEAL_") {
            child_cmd.env_remove(&env_key);
        }
    }

    let decrypted_envs = resolve::resolve_secrets(&vault, group, tag, token_file, allow_env)?;

    if decrypted_envs.is_empty() && !vault.list_all_keys(group, tag)?.is_empty() {
        anyhow::bail!("Execution aborted: No secrets could be decrypted for this scope!!");
    }

    for (key, value) in decrypted_envs {
        child_cmd.env(&key, value.as_str());
    }

    let mut child = child_cmd
        .spawn()
        .with_context(|| format!("Failed to start process '{}'", cmd_name))?;

    let status = child.wait().context("Failed to wait on child process!!")?;

    if let Some(code) = status.code() {
        Ok(code)
    } else {
        Ok(1)
    }
}

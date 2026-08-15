use crate::utils::{resolve, vault::Vault};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::{exit, Command};

pub fn cmd_run(
    group: Option<&str>,
    tag: Option<&str>,
    args: Vec<&str>,
    token_file: Option<&PathBuf>,
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let (cmd_name, cmd_args) = args.split_first().context("No command provided to run!!")?;

    let vault = Vault::load(global, pref)?;

    let mut child_cmd = Command::new(cmd_name);
    child_cmd.args(cmd_args);

    let decrypted_envs = resolve::resolve_secrets(&vault, group, tag, token_file)?;

    for (key, value) in decrypted_envs {
        child_cmd.env(&key, value.as_str());
    }

    let mut child = child_cmd
        .spawn()
        .with_context(|| format!("Failed to start process '{}'", cmd_name))?;

    let status = child.wait().context("Failed to wait on child process!!")?;

    if let Some(code) = status.code() {
        exit(code);
    } else {
        exit(1);
    }
}

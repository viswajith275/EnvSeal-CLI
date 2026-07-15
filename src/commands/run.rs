use anyhow::{Context, Result};
use std::process::Command;
use zeroize::Zeroize;

use crate::utils::vault::Vault;

pub fn cmd_run(args: Vec<String>) -> Result<()> {

    let (cmd_name, cmd_args) = args.split_first()
        .context("No command provided to run")?;

    let vault = Vault::load()?;
    let password: String = rpassword::prompt_password("Enter Master Password: ")?;
    let derived = vault.unlock(&password)?;

    let mut child_cmd = Command::new(cmd_name);
    child_cmd.args(cmd_args);

    for key in vault.list_all_keys().unwrap() {

        let value = vault.get_entry(&derived, &key);

        let mut value = match value {
            Ok(value) => value,
            Err(_) => panic!("Error while loading enviornment variables!")
        };
        child_cmd.env(key, &value);
        
        value.zeroize(); 
    }

    let mut child = child_cmd.spawn()
        .with_context(|| format!("Failed to start process '{}'", cmd_name))?;
        
    let status = child.wait().context("Failed to wait on child process")?;

    if let Some(code) = status.code() {
        std::process::exit(code);
    } else {
        std::process::exit(1);
    }
}
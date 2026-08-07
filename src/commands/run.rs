use crate::utils::vault::Vault;
use anyhow::{Context, Result};
use rpassword::prompt_password;
use std::process::Command;
use zeroize::{Zeroize, Zeroizing};

pub fn cmd_run(group: Option<&str>, tag: Option<&str>, args: Vec<&str>) -> Result<()> {
    let (cmd_name, cmd_args) = args.split_first().context("No command provided to run!!")?;

    let vault = Vault::load()?;
    let password: String = rpassword::prompt_password("Master Password: ")?;
    let derived = vault.unlock(&password)?;

    let mut child_cmd = Command::new(cmd_name);
    child_cmd.args(cmd_args);

    let mut tag_password: Option<Zeroizing<String>> = None;

    if vault.is_tag_protected(group, tag)? {
        tag_password = Some(Zeroizing::new(prompt_password("Tag Password: ")?));
    }

    let base_keys = vault.list_all_keys(group, None)?;
    for key in base_keys {
        let mut value = vault
            .get_entry(
                &derived.enc_key,
                group,
                None,
                &key,
                tag_password.as_ref().map(|s| s.as_str()),
            )
            .with_context(|| format!("Failed to read base key '{key}'"))?;

        child_cmd.env(&key, &value);

        value.zeroize();
    }

    if tag.is_some() {
        let tag_keys = vault.list_all_keys(group, tag)?;
        for key in tag_keys {
            let mut value = vault
                .get_entry(
                    &derived.enc_key,
                    group,
                    tag,
                    &key,
                    tag_password.as_ref().map(|s| s.as_str()),
                )
                .with_context(|| format!("Failed to read tag key '{key}'"))?;

            child_cmd.env(&key, &value);

            value.zeroize();
        }
    }

    let mut child = child_cmd
        .spawn()
        .with_context(|| format!("Failed to start process '{}'", cmd_name))?;

    let status = child.wait().context("Failed to wait on child process!!")?;

    if let Some(code) = status.code() {
        std::process::exit(code);
    } else {
        std::process::exit(1);
    }
}

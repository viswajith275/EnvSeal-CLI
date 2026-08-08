use crate::utils::{unlock, vault::Vault};
use anyhow::{anyhow, Context, Result};
use std::process::Command;
use zeroize::Zeroize;

pub fn cmd_run(
    group: Option<&str>,
    tag: Option<&str>,
    args: Vec<&str>,
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let (cmd_name, cmd_args) = args.split_first().context("No command provided to run!!")?;

    let vault = Vault::load(global, pref)?;
    let derived = unlock::sudo_unlock(&vault)?;

    let mut tag_key = None;
    if vault.is_tag_protected(group, tag)? {
        if let Some(t) = tag {
            tag_key = Some(unlock::sudo_unlock_tag(&vault, group, t)?);
        } else {
            return Err(anyhow!(
                "A tag must be provided if the group's default tag is protected."
            ));
        }
    }

    let mut child_cmd = Command::new(cmd_name);
    child_cmd.args(cmd_args);

    let base_keys = vault.list_all_keys(group, None)?;
    for key in base_keys {
        let mut value = vault
            .get_entry(&derived.enc_key, group, None, &key, tag_key.as_deref())
            .with_context(|| format!("Failed to read base key '{key}'"))?;

        child_cmd.env(&key, &value);

        value.zeroize();
    }

    if tag.is_some() {
        let tag_keys = vault.list_all_keys(group, tag)?;
        for key in tag_keys {
            let mut value = vault
                .get_entry(&derived.enc_key, group, tag, &key, tag_key.as_deref())
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

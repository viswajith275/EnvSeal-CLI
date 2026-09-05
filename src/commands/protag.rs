use crate::utils::{unlock, vault::Vault};
use anyhow::{bail, Result};

pub fn cmd_protag(
    group: Option<&str>,
    tag: &str,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;
    let group_name = vault.resolve_group_name(group)?;
    let master_keys = unlock::sudo_unlock(&vault, None, allow_env)?;

    let prompt_msg = format!("password for tag '{}' in group '{}': ", tag, group_name);
    let tag_password = unlock::prompt_with_fallback(&prompt_msg)?;
    let confirm_msg = format!("confirm password for tag '{}': ", tag);
    let confirm = unlock::prompt_with_fallback(&confirm_msg)?;
    if *tag_password != *confirm {
        bail!("Passwords did not match!");
    }

    vault.create_protected_tag(&master_keys.signing_key, group, tag, tag_password.as_str())?;

    vault.save()?;
    let location_label = if vault.is_local() { "local" } else { "global" };
    eprintln!(
        "successfully created a protectored tag '{}' in group '{}' {} seal!",
        tag, group_name, location_label
    );
    Ok(())
}

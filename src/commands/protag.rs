use crate::utils::{unlock, vault::Vault};
use anyhow::{bail, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;
pub fn cmd_protag(group: Option<&str>, tag: &str, global: bool) -> Result<()> {
    let mut vault = Vault::load(global)?;
    let group_name = vault.resolve_group_name(group)?;
    let derived = unlock::sudo_unlock(&vault)?;

    let tag_password = Zeroizing::new(prompt_password(format!(
        "password for tag '{}' in group '{}': ",
        tag, group_name
    ))?);
    let confirm = Zeroizing::new(prompt_password(format!(
        "confirm password for tag '{}': ",
        tag
    ))?);
    if *tag_password != *confirm {
        bail!("Passwords did not match!");
    }

    vault.create_protected_tag(&derived.hmac_key, group, tag, tag_password.as_str())?;

    vault.save()?;
    let location_label = if vault.is_local() { "local" } else { "global" };
    eprintln!(
        "successfully created a protectored tag '{}' in group '{}' {} seal!",
        tag, group_name, location_label
    );
    Ok(())
}

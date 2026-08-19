use crate::utils::{unlock, vault::Vault};
use anyhow::{bail, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_passwd(global: bool, pref: Option<&str>, allow_env: bool) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, None, allow_env)?;

    let new_password = Zeroizing::new(prompt_password("enter new master password: ")?);
    if new_password.trim().is_empty() {
        bail!("Master password cannot be empty!!");
    }

    let confirm = Zeroizing::new(prompt_password("confirm new master password: ")?);
    if *new_password != *confirm {
        bail!("Passwords did not match!!");
    }

    vault.change_master_password(&master_keys, new_password.as_str())?;

    let location = if vault.is_local() { "local" } else { "global" };
    let env_suffix = pref
        .map(|p| format!(" [profile: .{p}.envseal]"))
        .unwrap_or_default();
    eprintln!("successfully changed master password for {location} vault{env_suffix}!");
    Ok(())
}

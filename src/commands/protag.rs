use crate::utils::vault::Vault;
use anyhow::{bail, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;
pub fn cmd_protag(group: Option<&str>, tag: &str) -> Result<()> {
    let mut vault = Vault::load()?;

    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let tag_password = Zeroizing::new(prompt_password("Tag Password: ")?);
    let confirm = Zeroizing::new(prompt_password("Confirm Tag Password: ")?);
    if *tag_password != *confirm {
        bail!("Passwords did not match!");
    }

    vault.create_protected_tag(&derived.hmac_key, group, tag, tag_password.as_str())?;

    vault.save()?;
    eprintln!("Successfully created a protectored tag '{}'!", tag);
    Ok(())
}

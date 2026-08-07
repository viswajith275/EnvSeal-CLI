use crate::utils::vault::Vault;
use anyhow::{Context, Ok, Result};
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_get(group: Option<&str>, tag: Option<&str>, key: &str) -> Result<()> {
    let vault = Vault::load()?;
    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let mut tag_password: Option<Zeroizing<String>> = None;

    if vault.is_tag_protected(group, tag)? {
        tag_password = Some(Zeroizing::new(prompt_password("Tag Password: ")?));
    }

    let value = vault
        .get_entry(
            &derived.enc_key,
            group,
            tag,
            key,
            tag_password.as_ref().map(|s| s.as_str()),
        )
        .with_context(|| format!("Failed to read '{key}'"))?;

    println!("{}", value.as_str());
    Ok(())
}

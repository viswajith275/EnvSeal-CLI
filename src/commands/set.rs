use crate::utils::vault::Vault;
use anyhow::Result;
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_set(group: Option<&str>, tag: Option<&str>, key: &str) -> Result<()> {
    let mut vault = Vault::load()?;

    let password = Zeroizing::new(prompt_password("Master Password: ")?);
    let derived = vault.unlock(&password)?;

    let mut tag_password: Option<Zeroizing<String>> = None;
    if vault.is_tag_protected(group, tag)? {
        tag_password = Some(Zeroizing::new(prompt_password("Tag Password: ")?));
    }

    let secret = Zeroizing::new(prompt_password(&format!("Value for {key}: "))?);

    vault.set_entry(
        &derived,
        group,
        tag,
        key,
        &secret,
        tag_password.as_ref().map(|s| s.as_str()),
    )?;

    vault.save()?;

    eprintln!("Stored {key} inside group");
    Ok(())
}

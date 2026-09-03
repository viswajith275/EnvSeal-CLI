use crate::utils::{
    unlock,
    vault::{Vault, BASE_TAG},
};
use anyhow::{Context, Result};
use std::env;
use zeroize::Zeroizing;

pub fn cmd_rotate(
    group: Option<&str>,
    tag: Option<&str>,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;
    let group_name = vault.resolve_group_name(group)?;

    let master_keys = unlock::sudo_unlock(&vault, None, allow_env)?;

    // Authenticate Tag (If Protected)
    let old_tag_dek = if vault.is_tag_protected(group, tag)? {
        Some(unlock::sudo_unlock_tag(
            &vault,
            group,
            tag.context("Tag not found!!")?,
            None,
            allow_env,
        )?)
    } else {
        None
    };

    let tag_password = if vault.is_tag_protected(group, tag)? {
        let active_tag = tag.context("Tag not found!!")?;
        let prompt = format!(
            "[sudo] password for tag '{}' in group '{}': ",
            active_tag, group_name
        );

        let pass = if allow_env {
            let env_tag_var = format!(
                "ENVSEAL_TAG_PASSWORD_{}",
                active_tag.to_uppercase().replace('-', "_")
            );
            if let Ok(env_pass) =
                env::var(&env_tag_var).or_else(|_| env::var("ENVSEAL_TAG_PASSWORD"))
            {
                if !env_pass.is_empty() {
                    Zeroizing::new(env_pass)
                } else {
                    Zeroizing::new(rpassword::prompt_password(prompt)?)
                }
            } else {
                Zeroizing::new(rpassword::prompt_password(prompt)?)
            }
        } else {
            Zeroizing::new(rpassword::prompt_password(prompt)?)
        };
        Some(pass)
    } else {
        None
    };

    eprintln!("re-encrypting scope and rotating DEK...");

    vault.rotate_scope_dek(
        &master_keys,
        group,
        tag,
        old_tag_dek.as_deref(),
        tag_password.as_ref().map(|z| z.as_str()),
    )?;

    vault.save()?;
    let _ = crate::utils::session::SessionManager::clear_session(
        &vault.tag_scope(group, tag.unwrap_or("base"))?,
    );

    eprintln!(
        "successfully rotated DEK for group '{}' and tag '{}'. All old tokens are now invalid.",
        group_name,
        tag.unwrap_or(BASE_TAG)
    );

    Ok(())
}

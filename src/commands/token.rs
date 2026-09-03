use crate::utils::{
    crypto,
    token::TokenManager,
    unlock,
    vault::{Vault, BASE_TAG},
};
use anyhow::{anyhow, Context, Result};
use fs2::FileExt;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

pub fn cmd_token(
    group: Option<&str>,
    tag: Option<&str>,
    name: &str,
    desc: Option<&str>,
    out_file: Option<&PathBuf>,
    allowed_keys: Vec<String>,
    ttl_seconds: Option<u64>,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, None, allow_env)?;

    let group_name = vault.resolve_group_name(group)?;
    let active_tag = tag.unwrap_or(BASE_TAG);
    let group_entry = vault
        .entries
        .get(&group_name)
        .context("Group not found!!")?;

    let base_scope_dek = crypto::derive_scope_dek(&master_keys.master_dek, &group_name, BASE_TAG);

    let tag_scope_dek = if active_tag != BASE_TAG {
        if vault.is_tag_protected(group, tag)? {
            let unwrapped = unlock::sudo_unlock_tag(&vault, group, active_tag, None, allow_env)?;
            Some(*unwrapped)
        } else {
            Some(crypto::derive_scope_dek(
                &master_keys.master_dek,
                &group_name,
                active_tag,
            ))
        }
    } else {
        None
    };

    let mut resolved_map: HashMap<String, [u8; 32]> = HashMap::new();

    for base_key in group_entry.base.keys() {
        resolved_map.insert(base_key.clone(), base_scope_dek);
    }

    if let Some(tag_dek) = tag_scope_dek {
        let tag_entry = group_entry
            .tags
            .get(active_tag)
            .context("Group not found!!")?;
        for tag_key in tag_entry.entries.keys() {
            resolved_map.insert(tag_key.clone(), tag_dek);
        }
    }

    if !allowed_keys.is_empty() {
        let explicit_set: HashSet<String> = allowed_keys.into_iter().collect();
        resolved_map.retain(|k, _| explicit_set.contains(k));
    }

    if resolved_map.is_empty() {
        return Err(anyhow!(
            "Cannot create token: No variables found or allowed for this scope."
        ));
    }

    let mut final_token_keys = HashMap::new();
    for (var_name, active_scope_dek) in resolved_map {
        let entry_key = crypto::derive_entry_key(&active_scope_dek, &var_name);
        final_token_keys.insert(var_name, zeroize::Zeroizing::new(entry_key.to_vec()));
    }

    let scope_string = vault.tag_scope(group, active_tag)?;
    let token_string = TokenManager::create(
        &master_keys.signing_key,
        &scope_string,
        final_token_keys,
        name,
        ttl_seconds,
        desc,
    )?;

    if let Some(path) = out_file {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }

        file.lock_exclusive()?;

        let write_result = file.write_all(token_string.as_bytes());

        let unlock_result = file.unlock();

        write_result?;
        unlock_result?;

        #[cfg(unix)]
        eprintln!(
            "token successfully written to '{}' (permissions set to 0600)",
            path.display()
        );

        #[cfg(windows)]
        eprintln!(
               "token successfully written to '{}'. Note: on Windows, file permissions are not \
                explicitly restricted — ensure the containing directory has appropriate access controls.",
               path.display()
           );
    } else {
        eprintln!("token generated successfully. Pass this via ENVSEAL_TOKEN or --token-file \n");
        println!("{}", token_string);
    }

    Ok(())
}

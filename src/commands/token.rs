use crate::utils::{
    crypto,
    token::TokenManager,
    unlock,
    vault::{Vault, BASE_TAG},
};
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt; // For chmod 600

pub fn cmd_token(
    group: Option<&str>,
    tag: Option<&str>,
    name: &str,
    desc: Option<&str>,
    out_file: Option<&std::path::PathBuf>,
    allowed_keys: Vec<String>,
    ttl_seconds: Option<u64>,
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault)?;

    let group_name = vault.resolve_group_name(group)?;
    let active_tag = tag.unwrap_or(BASE_TAG);
    let group_entry = vault.entries.get(&group_name).unwrap();

    let base_scope_dek = crypto::derive_scope_dek(&master_keys.master_dek, &group_name, BASE_TAG);

    let tag_scope_dek = if active_tag != BASE_TAG {
        if vault.is_tag_protected(group, tag)? {
            let unwrapped = unlock::sudo_unlock_tag(&vault, group, active_tag)?;
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
        let tag_entry = group_entry.tags.get(active_tag).unwrap();
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
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;

        file.write_all(token_string.as_bytes())?;
        eprintln!(
            "token successfully written to '{}' (Permissions restricted to 600)",
            path.display()
        );
    } else {
        eprintln!("token generated successfully, pass this via ENVSEAL_TOKEN or --token-file \n");
        println!("{}", token_string);
    }

    Ok(())
}

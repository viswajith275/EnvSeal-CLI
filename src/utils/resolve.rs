use super::token::TokenManager;
use super::unlock;
use super::vault::Vault;
use super::vault::BASE_TAG;
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Safely retrieves the token without exposing it to process monitors
pub fn fetch_token_from_diffrent_ends(token_file_path: Option<&PathBuf>) -> Result<Option<String>> {
    let file_path = token_file_path
        .map(|p| p.to_path_buf())
        .or_else(|| env::var("ENVSEAL_TOKEN_FILE").ok().map(|s| s.into()));

    if let Some(path) = file_path {
        if !path.exists() {
            return Err(anyhow!("Token file not found at: {}", path.display()));
        }
        let token =
            fs::read_to_string(&path).map_err(|e| anyhow!("Failed to read token file: {}", e))?;

        return Ok(Some(token.trim().to_string()));
    }

    if let Ok(token) = env::var("ENVSEAL_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(Some(token.trim().to_string()));
        }
    }

    if !io::stdin().is_terminal() {
        let mut buffer = String::new();
        if io::stdin().read_to_string(&mut buffer).is_ok() {
            let token = buffer.trim().to_string();
            if token.starts_with("envseal_") {
                return Ok(Some(token));
            }
        }
    }

    Ok(None)
}

/// Universally resolves variables, seamlessly switching between Token and Password modes.
pub fn resolve_secrets(
    vault: &Vault,
    group: Option<&str>,
    tag: Option<&str>,
    token_file: Option<&PathBuf>,
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let active_tag = tag.unwrap_or(BASE_TAG);

    if let Some(token_str) = fetch_token_from_diffrent_ends(token_file)? {
        eprintln!("Secure token detected! Executing in Zero-Trust offline mode...");
        let payload = TokenManager::verify_and_extract(&token_str, &vault.public_key)?;

        let expected_scope = vault.tag_scope(group, active_tag)?;
        if payload.scope != expected_scope {
            return Err(anyhow!("Access Denied: Token scope mismatch!"));
        }

        // Return decrypted map directly from token
        return vault.decrypt_from_token(group, tag, &payload);
    }

    // Fallback to Password Mode
    let master_keys = unlock::sudo_unlock(vault)?;
    let tag_key = if vault.is_tag_protected(group, tag)? {
        Some(unlock::sudo_unlock_tag(vault, group, active_tag)?)
    } else {
        None
    };
    let keys = vault.list_all_keys(group, tag)?;
    let mut decrypted_envs = BTreeMap::new();

    for key in keys {
        match vault.get_entry(
            &master_keys.master_dek,
            group,
            tag,
            &key,
            tag_key.as_deref(),
        ) {
            Ok(value) => {
                decrypted_envs.insert(key, value);
            }
            Err(_) => continue,
        }
    }

    Ok(decrypted_envs)
}

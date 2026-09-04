use super::token::TokenManager;
use super::unlock;
use super::vault::{Vault, BASE_TAG};
use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Safely retrieves the token from disk, environment, or stdin without leaking into memory dumps.
pub fn fetch_token(
    token_file_path: Option<&PathBuf>,
    allow_env: bool,
) -> Result<Option<Zeroizing<String>>> {
    let file_path = token_file_path.cloned().or_else(|| {
        if allow_env {
            env::var("ENVSEAL_TOKEN_FILE").ok().map(PathBuf::from)
        } else {
            None
        }
    });

    if let Some(path) = file_path {
        let mut raw = Zeroizing::new(if path.as_os_str() == "-" {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            buffer
        } else {
            if !path.exists() {
                return Err(anyhow!("Token file not found at: {}", path.display()));
            }
            fs::read_to_string(&path)?
        });

        let trimmed = raw.trim();
        let trimmed_len = trimmed.len();
        raw.truncate(trimmed_len);
        return Ok(Some(raw));
    }

    if allow_env {
        if let Ok(mut token) = env::var("ENVSEAL_TOKEN") {
            let trimmed_len = token.trim().len();
            token.truncate(trimmed_len);
            if !token.is_empty() {
                return Ok(Some(Zeroizing::new(token)));
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
    allow_env: bool,
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    // Verify file integrity upfront before querying entries or public keys
    vault.verify_integrity()?;

    // Zero-Trust Token Mode
    if let Some(token_str) = fetch_token(token_file, allow_env)? {
        eprintln!("Secure token detected! Executing in Zero-Trust offline mode...");
        let payload = TokenManager::verify_and_extract(&token_str, &vault.public_key)?;

        let active_tag = match tag {
            Some(t) => {
                let expected_scope = vault.tag_scope(group, t)?;
                if payload.scope != expected_scope {
                    return Err(anyhow!("Access Denied: Token scope mismatch!"));
                }
                t.to_string()
            }
            None => {
                let (token_group, token_tag) =
                    vault.parse_scope(&payload.scope).ok_or_else(|| {
                        anyhow!("Access Denied: Token was not issued for this vault!")
                    })?;
                let resolved_group = vault.resolve_group_name(group)?;
                if token_group != resolved_group {
                    return Err(anyhow!("Access Denied: Token group mismatch!"));
                }
                token_tag.to_string()
            }
        };

        // Pass Some(&active_tag) to ensure inferred tag overrides are applied
        return vault.decrypt_from_token(group, Some(&active_tag), &payload);
    }

    // Password Mode
    let active_tag = tag.unwrap_or(BASE_TAG);
    let master_keys = unlock::sudo_unlock(vault, None, allow_env)?;
    let tag_key = if vault.is_tag_protected(group, Some(active_tag))? {
        Some(unlock::sudo_unlock_tag(
            vault, group, active_tag, None, allow_env,
        )?)
    } else {
        None
    };

    let keys = vault.list_all_keys(group, Some(active_tag))?;
    let mut decrypted_envs = BTreeMap::new();

    for key in keys {
        let value = vault
            .get_entry(
                &master_keys.master_dek,
                group,
                Some(active_tag),
                &key,
                tag_key.as_deref(),
            )
            .with_context(|| format!("Failed to decrypt secret '{key}'"))?;

        decrypted_envs.insert(key, value);
    }

    Ok(decrypted_envs)
}

use super::token::TokenManager;
use super::unlock;
use super::vault::{Vault, BASE_TAG};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use zeroize::Zeroizing;

// helper which analyse and parse token, stdin and token path
pub fn load_token(cli_token: Option<&str>) -> Result<Option<String>> {
    if let Some(target) = cli_token {
        let trimmed = target.trim();
        if trimmed == "-" {
            let mut buf = String::new();
            io::stdin().take(16 * 1024).read_to_string(&mut buf)?;
            return Ok(Some(buf.trim().to_string()));
        }
        if Path::new(trimmed).exists() {
            let content = fs::read_to_string(trimmed)?;
            return Ok(Some(content.trim().to_string()));
        }
        return Ok(Some(trimmed.to_string()));
    }

    if let Ok(env_tok) = std::env::var("ENVSEAL_TOKEN") {
        let trimmed = env_tok.trim();
        if !trimmed.is_empty() {
            if Path::new(trimmed).exists() {
                let content = fs::read_to_string(trimmed)?;
                return Ok(Some(content.trim().to_string()));
            }
            return Ok(Some(trimmed.to_string()));
        }
    }

    Ok(None)
}

/// Universally resolves variables, seamlessly switching between Token and Password modes.
pub fn resolve_environment(
    vault: &Vault,
    group: Option<&str>,
    tag: Option<&str>,
    token: Option<&str>,
    allow_env: bool,
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    // 1. Offline Token Mode (Zero-Trust / CI)
    if let Some(token_str) = token {
        let payload = TokenManager::verify_and_extract(token_str, &vault.public_key)?;
        let active_tag = tag.unwrap_or(BASE_TAG);
        let expected_scope = vault.tag_scope(group, active_tag)?;
        if payload.scope != expected_scope {
            anyhow::bail!(
                "Token scope mismatch: token is scoped for '{}', but active scope is '{}'",
                payload.scope,
                expected_scope
            );
        }
        return vault.decrypt_from_token(group, tag, &payload);
    }

    // Identity / Master Key Mode
    let active_tag = tag.unwrap_or(BASE_TAG);
    let master_keys = unlock::sudo_unlock(vault, None, allow_env)?;
    let keys = vault.list_all_keys(group, Some(active_tag))?;
    let mut decrypted_envs = BTreeMap::new();
    for key in keys {
        let value = vault
            .get_entry(&master_keys.master_dek, group, Some(active_tag), &key)
            .with_context(|| format!("Failed to decrypt secret '{key}'"))?;
        decrypted_envs.insert(key, value);
    }
    Ok(decrypted_envs)
}

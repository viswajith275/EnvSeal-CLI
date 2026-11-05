use crate::utils::vault::DecryptedValue;

use super::token::TokenManager;
use super::unlock;
use super::vault::{Vault, BASE_TAG};
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct OverrideVals<'a> {
    pub keys: &'a [String],
    pub with_global: bool,
    pub global_group: Option<&'a str>,
    pub global_tag: Option<&'a str>,
}

impl<'a> OverrideVals<'a> {
    pub fn is_active(&self) -> bool {
        self.with_global || !self.keys.is_empty()
    }
}

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

/// Returns the current Git branch when it has a matching tag in the vault
pub fn auto_tag(vault: &Vault, group: Option<&str>, tag: Option<&str>) -> Option<String> {
    if tag.is_some() {
        return tag.map(str::to_string);
    }
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let branch = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let grp = vault.resolve_group_name(group).ok()?;
    vault
        .entries
        .get(&grp)?
        .tags
        .contains_key(&branch)
        .then_some(branch)
}

/// Universally resolves variables, seamlessly switching between Token and Age
pub fn resolve_environment(
    vault: &Vault,
    group: Option<&str>,
    tag: Option<&str>,
    token: Option<&str>,
    allow_env: bool,
    overrides: Option<&OverrideVals>,
) -> Result<BTreeMap<String, DecryptedValue>> {
    let is_override_active = overrides.is_some_and(|o| o.is_active());

    if is_override_active && !vault.is_local() {
        anyhow::bail!(
            "Conflict: Cannot apply global overrides when already targeting a global vault."
        );
    }

    let mut decrypted_envs = if let Some(token_str) = token {
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
        vault.decrypt_from_token(group, tag, &payload)?
    } else {
        let active_tag = tag.unwrap_or(BASE_TAG);
        let master_keys = unlock::sudo_unlock(vault, None, allow_env)?;
        vault.decrypt_all(&master_keys.master_dek, group, Some(active_tag))?
    };

    if let Some(vals) = overrides {
        if vals.is_active() {
            apply_global_overrides(&mut decrypted_envs, vals, allow_env)?;
        }
    }

    Ok(decrypted_envs)
}

fn apply_global_overrides(
    decrypted_envs: &mut BTreeMap<String, DecryptedValue>,
    vals: &OverrideVals,
    allow_env: bool,
) -> Result<()> {
    let global_vault = Vault::load(true, None).map_err(|e| {
        anyhow!("Global vault not found or could not be loaded for overrides (run 'envseal init -G'): {e}")
    })?;

    let target_group = match vals.global_group {
        Some(g) => g.to_string(),
        None => global_vault.resolve_group_name(None)?,
    };

    let target_tag = vals.global_tag.unwrap_or(BASE_TAG);
    let master_keys = unlock::sudo_unlock(&global_vault, Some("global overrides"), allow_env)?;

    let mut available_globals = global_vault.decrypt_all(
        &master_keys.master_dek,
        Some(&target_group),
        Some(target_tag),
    )?;
    let mut override_count = 0;

    if vals.with_global {
        // fetch all keys and override local keys
        for (key, val) in available_globals {
            decrypted_envs.insert(key, val);
            override_count += 1;
        }
    } else {
        // fetch the values of specified keys and override/insert them
        for raw_key in vals.keys {
            let key = raw_key.trim();
            if key.is_empty() {
                continue;
            }

            if let Some(val) = available_globals.remove(key) {
                decrypted_envs.insert(key.to_string(), val);
                override_count += 1;
            } else {
                eprintln!(
                            "Warning: Override key '{key}' was not found in global vault (group: '{target_group}', tag: '{target_tag}'). Skipping...!!!"
                        );
            }
        }
    }

    if override_count > 0 {
        eprintln!(
                "[envseal] Overrided {override_count} variable(s) from global vault (group: '{target_group}', tag: '{target_tag}')"
            );
    }

    Ok(())
}

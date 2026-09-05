use crate::utils::is_valid_env_key;
use crate::utils::{unlock, vault::Vault};
use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Read};

pub fn cmd_import(
    group: Option<&str>,
    tag: Option<&str>,
    file_path: &str,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    let raw = if file_path == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read import file '{}'", file_path))?
    };

    let mut vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, Some("import"), allow_env)?;

    let mut imported = 0;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // clear export prefix
        let line_clean = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some((k, v)) = line_clean.split_once('=') {
            let key = k.trim();
            if !is_valid_env_key(key) {
                eprintln!("Warning: skipping invalid key '{key}'");
                continue;
            }

            let val = v.trim().trim_matches(|c| c == '"' || c == '\'');
            vault.set_entry(&master_keys, group, tag, key, val)?;
            imported += 1;
        }
    }

    vault.save()?;
    eprintln!("Successfully imported {imported} variable(s).");
    Ok(())
}

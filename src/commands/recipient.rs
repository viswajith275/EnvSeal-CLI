use crate::utils::{envelope, vault::Vault};
use anyhow::Context;
use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

// caps stdin and file inputs at 64KB, update if needed
fn read_recipient_input(target: &str) -> Result<String> {
    // if start with @ fetch ssh keys from github
    if let Some(username) = target.strip_prefix('@') {
        // calls curl to fetch GitHub keys
        let out = std::process::Command::new("curl")
            .args(["-sSfL", &format!("https://github.com/{username}.keys")])
            .output()
            .with_context(|| format!("Failed to run curl for @{username}"))?;
        if !out.status.success() {
            anyhow::bail!("Failed to fetch keys for GitHub user '@{username}'");
        }
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let mut buffer = String::new();
    if target == "-" {
        io::stdin().take(64 * 1024).read_to_string(&mut buffer)?;
    } else if Path::new(target).exists() {
        File::open(target)?
            .take(64 * 1024)
            .read_to_string(&mut buffer)?;
    } else {
        return Ok(target.to_string());
    }
    Ok(buffer)
}

fn extract_valid_keys(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| {
            l.parse::<age::x25519::Recipient>().is_ok() || l.parse::<age::ssh::Recipient>().is_ok()
        })
        .map(ToString::to_string)
        .collect()
}

pub fn cmd_identity() -> Result<()> {
    let pubkey = envelope::get_or_create_default_recipient()?;
    println!("{pubkey}");
    Ok(())
}

pub fn cmd_add(target: &str, global: bool, pref: Option<&str>, allow_env: bool) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;
    let raw = read_recipient_input(target)?;
    let incoming = extract_valid_keys(&raw);

    if incoming.is_empty() {
        return Err(anyhow!("No valid Age or SSH public keys found in input!!"));
    }

    let to_add: Vec<String> = incoming
        .into_iter()
        .filter(|key| !vault.recipients.contains(key))
        .collect();

    if to_add.is_empty() {
        eprintln!("Recipient(s) already present in vault.");
        return Ok(());
    }

    // Unlock and verify existing envelope integrity before mutating recipients
    let keys = vault.unlock(allow_env)?;
    let added = to_add.len();
    vault.recipients.extend(to_add);

    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(&*keys.master_dek);
    payload[32..].copy_from_slice(keys.signing_key.to_bytes().as_slice());

    vault.envelope = envelope::wrap_envelope(&payload, &vault.recipients)?;
    vault.seal_integrity(&keys.signing_key)?;
    vault.save()?;

    eprintln!("added {added} recipient(s). Vault re-encrypted.");
    Ok(())
}

pub fn cmd_list(global: bool, pref: Option<&str>) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    for (i, r) in vault.recipients.iter().enumerate() {
        let (key, name) = r
            .split_once('#')
            .map(|(k, n)| (k.trim(), n.trim()))
            .unwrap_or((r.trim(), ""));

        if name.is_empty() {
            println!("[{i}] {key}");
        } else {
            println!("[{i}] {name:<12} ({key})");
        }
    }
    Ok(())
}

pub fn cmd_remove(target: &str, global: bool, pref: Option<&str>, allow_env: bool) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;

    // linear scan over recipients
    let idx = if let Ok(i) = target.parse::<usize>() {
        if i < vault.recipients.len() {
            Some(i)
        } else {
            None
        }
    } else {
        vault.recipients.iter().position(|r| {
            let (k, name) = r
                .split_once('#')
                .map(|(k, n)| (k.trim(), n.trim()))
                .unwrap_or((r.trim(), ""));
            r == target || k == target || name.eq_ignore_ascii_case(target)
        })
    };

    let Some(target_idx) = idx else {
        return Err(anyhow!(
            "Recipient '{target}' not found by name, index, or key."
        ));
    };

    if vault.recipients.len() <= 1 {
        return Err(anyhow!(
            "Cannot remove the last recipient. Vault would become unrecoverable."
        ));
    }

    let keys = vault.unlock(allow_env)?;
    let removed = vault.recipients.remove(target_idx);

    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(&*keys.master_dek);
    payload[32..].copy_from_slice(keys.signing_key.to_bytes().as_slice());
    vault.envelope = envelope::wrap_envelope(&payload, &vault.recipients)?;
    vault.seal_integrity(&keys.signing_key)?;
    vault.save()?;
    let _ = crate::utils::session::SessionManager::clear_session(&vault.master_scope());

    eprintln!("Removed recipient '{removed}'. Vault re-encrypted.");
    Ok(())
}

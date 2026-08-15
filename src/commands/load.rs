use crate::utils::{resolve, vault::Vault};
use anyhow::Result;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

/// Determines the target shell for proper syntax formatting and string escaping
#[derive(Debug)]
enum ShellType {
    Posix,
    Fish,
    PowerShell,
    Cmd,
}

impl ShellType {
    fn from_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.ends_with("fish") {
            ShellType::Fish
        } else if lower.ends_with("pwsh") || lower.ends_with("powershell") {
            ShellType::PowerShell
        } else if lower.ends_with("cmd") || lower.ends_with("cmd.exe") {
            ShellType::Cmd
        } else {
            // Default to POSIX (Bash, Zsh, Sh)
            ShellType::Posix
        }
    }
}

pub fn cmd_load(
    group: Option<&str>,
    tag: Option<&str>,
    keys: Vec<&str>,
    token_file: Option<&PathBuf>, // Added for token support
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let group_name = vault.resolve_group_name(group)?;

    let location_label = if vault.is_local() { "local" } else { "global" };

    let message = if let Some(t) = tag {
        match keys.is_empty() {
            true => format!(
                "loading envs from tag '{}' inside group '{}' {} seal!",
                t, group_name, location_label
            ),
            false => format!(
                "loading envs '{:?}' from tag '{}' inside group '{}' {} seal!",
                keys, t, group_name, location_label
            ),
        }
    } else {
        format!(
            "loading envs from group '{}' {} seal!",
            group_name, location_label
        )
    };

    eprintln!("{}", message);

    let mut decrypted_envs = resolve::resolve_secrets(&vault, group, tag, token_file)?;

    // filter derived to find specified keys
    if !keys.is_empty() {
        let requested_set: HashSet<&str> = keys.iter().copied().collect();
        decrypted_envs.retain(|k, _| requested_set.contains(k.as_str()));

        for key in &keys {
            if !decrypted_envs.contains_key(*key) {
                eprintln!(
                        " Warning: '{}' was not found in the vault, or the provided token lacks permission to decrypt it. Skipping...",
                        key
                    );
            }
        }
    }

    let mut sorted_envs: BTreeMap<String, String> = BTreeMap::new();
    for (key, mut value) in decrypted_envs {
        sorted_envs.insert(key, value.to_string());
        zeroize::Zeroize::zeroize(&mut value);
    }

    let shell_name = std::env::var("SHELL")
        .ok()
        .unwrap_or_else(|| "posix".to_string());

    let shell = ShellType::from_name(&shell_name);

    for (key, value) in sorted_envs {
        match shell {
            ShellType::Posix => {
                let escaped_val = value.replace('\'', "'\\''");
                println!("export {}='{}'", key, escaped_val);
            }
            ShellType::Fish => {
                let escaped_val = value.replace('\\', "\\\\").replace('\'', "\\'");
                println!("set -gx {} '{}'", key, escaped_val);
            }
            ShellType::PowerShell => {
                let escaped_val = value.replace('\'', "''");
                println!("$env:{}='{}'", key, escaped_val);
            }
            ShellType::Cmd => {
                println!("set {}={}", key, value);
            }
        }
    }

    Ok(())
}

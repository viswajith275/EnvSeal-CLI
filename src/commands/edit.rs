use crate::utils::format_env_value;
use crate::utils::parse_env_lines;
use crate::utils::{crypto, unlock, vault::Entry, vault::Vault, vault::BASE_TAG, ShredOnDrop};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;

pub fn cmd_edit(
    group: Option<&str>,
    tag: Option<&str>,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    let mut vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, Some("edit"), allow_env)?;
    let group_name = vault.resolve_group_name(group)?;
    let active_tag = tag.unwrap_or(BASE_TAG);

    let (existing_text_keys, file_secrets): (Vec<String>, Vec<(String, String)>) =
        if let Some(g) = vault.entries.get(&group_name) {
            let mut text_k = Vec::new();
            let mut file_k = BTreeMap::new();
            for (k, entry) in &g.base {
                if let Some(ref env_name) = entry.file_env {
                    file_k.insert(k.clone(), env_name.clone());
                } else if active_tag == BASE_TAG {
                    text_k.push(k.clone());
                }
            }
            if active_tag != BASE_TAG {
                if let Some(t) = g.tags.get(active_tag) {
                    for (k, entry) in &t.entries {
                        if let Some(ref env_name) = entry.file_env {
                            file_k.insert(k.clone(), env_name.clone());
                        } else {
                            text_k.push(k.clone());
                        }
                    }
                }
            }
            (text_k, file_k.into_iter().collect())
        } else {
            (Vec::new(), Vec::new())
        };

    // Initial buffer
    let mut initial_content = String::new();
    initial_content.push_str(&format!(
        "# ==============================================================================\n\
         # envseal edit :: group='{group_name}', tag='{active_tag}'\n\
         # ==============================================================================\n"
    ));

    if !file_secrets.is_empty() {
        initial_content.push_str(
            "#\n\
             # ACTIVE FILE SECRETS (READ-ONLY IN THIS BUFFER)\n\
             # Decrypted to isolated temp paths during 'envseal run' and injected via:\n\
             #\n\
             #   SECRET IDENTIFIER          INJECTED ENV VARIABLE ($ENV_NAME)\n\
             #   ----------------------------------------------------------------------\n",
        );
        for (key, env_name) in &file_secrets {
            initial_content.push_str(&format!("#   {:<26} -> ${}\n", key, env_name));
        }
        initial_content.push_str(
            "#\n\
             # Note: Text variables below cannot reuse any of these keys or env_name values.\n\
             # To add/update: 'envseal set <KEY> --file <PATH> [--env-var <VAR>]'\n\
             # To remove:     'envseal remove <KEY>'\n\
             # ==============================================================================\n\n",
        );
    } else {
        initial_content.push_str(
            "# (No encrypted file secrets stored in this scope)\n\
             # ==============================================================================\n\n",
        );
    }

    for key in &existing_text_keys {
        if let Ok(val) = vault.get_entry(&master_keys.master_dek, Some(&group_name), tag, key) {
            initial_content.push_str(&format!("{key}={}\n", format_env_value(&val)));
        }
    }

    let mut temp = ShredOnDrop(NamedTempFile::new()?);
    temp.0.write_all(initial_content.as_bytes())?;
    temp.0.flush()?;

    let fallback = if cfg!(windows) { "notepad" } else { "nano" };
    let editor_var = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_default();

    let trimmed = editor_var.trim();

    let parts: Vec<String> = if trimmed.is_empty() {
        vec![fallback.to_string()]
    } else if Path::new(trimmed).is_file() {
        vec![trimmed.to_string()]
    } else {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;

        for c in trimmed.chars() {
            match c {
                '"' => in_quotes = !in_quotes,
                c if c.is_whitespace() && !in_quotes => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(c),
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }

        if tokens.is_empty() {
            vec![fallback.to_string()]
        } else {
            tokens
        }
    };

    let status = Command::new(&parts[0])
        .args(&parts[1..])
        .arg(temp.0.path())
        .status()
        .with_context(|| format!("Failed to run editor '{editor_var}' !!"))?;

    if !status.success() {
        anyhow::bail!("Editor exited with error status: {status}!!");
    }

    let mut updated_content = String::new();
    File::open(temp.0.path())?.read_to_string(&mut updated_content)?;
    drop(temp);

    if updated_content == initial_content {
        eprintln!("No changes made");
        return Ok(());
    }

    let parsed = parse_env_lines(&updated_content);
    let new_map: BTreeMap<String, String> = parsed.into_iter().collect();
    let new_keys: HashSet<&str> = new_map.keys().map(String::as_str).collect();

    for key in new_map.keys() {
        if let Some((_, _)) = file_secrets.iter().find(|(f_key, _)| f_key == key) {
            anyhow::bail!(
                "Collision: '{key}' matches an existing file secret identifier.\n\
                Use 'envseal remove {key}' first if you want to replace it with a text variable."
            );
        }
        if let Some((f_key, env_name)) = file_secrets.iter().find(|(_, env_name)| env_name == key) {
            anyhow::bail!(
                "Collision: '{key}' is already the target env variable (${env_name}) for file secret '{f_key}'.\n\
                 Injecting a text secret under this name would conflict during runtime execution."
            );
        }
    }

    let group_entry = vault.entries.entry(group_name.clone()).or_default();
    let scope_dek = crypto::derive_scope_dek(&master_keys.master_dek, &group_name, active_tag);

    for key in &existing_text_keys {
        if !new_keys.contains(key.as_str()) {
            if active_tag == BASE_TAG {
                group_entry.base.remove(key);
            } else if let Some(t) = group_entry.tags.get_mut(active_tag) {
                t.entries.remove(key);
            }
        }
    }

    for (key, val) in new_map {
        let entry_key = crypto::derive_entry_key(&scope_dek, &key);
        let (nonce, ciphertext) = crypto::encrypt(&entry_key, val.as_bytes())?;
        let entry = Entry {
            nonce: nonce.to_vec(),
            ciphertext,
            file_env: None,
            file_name: None,
            file_mode: None,
        };
        if active_tag == BASE_TAG {
            group_entry.base.insert(key, entry);
        } else {
            group_entry
                .tags
                .entry(active_tag.to_string())
                .or_default()
                .entries
                .insert(key, entry);
        }
    }

    vault.seal_integrity(&master_keys.signing_key)?;
    vault.save()?;
    eprintln!("vault updated successfully.");
    Ok(())
}

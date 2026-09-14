use crate::utils::format_env_value;
use crate::utils::parse_env_lines;
use crate::utils::{unlock, vault::Vault, vault::BASE_TAG};
use anyhow::{anyhow, Context, Result};
use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::Command;
use tempfile::NamedTempFile;

struct ShredOnDrop(NamedTempFile);

impl Drop for ShredOnDrop {
    fn drop(&mut self) {
        if let Ok(mut f) = OpenOptions::new().write(true).open(self.0.path()) {
            if let Ok(meta) = f.metadata() {
                let zeroes = vec![0u8; meta.len() as usize];
                let _ = f.write_all(&zeroes);
                let _ = f.sync_all();
            }
        }
    }
}

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

    let existing_keys: Vec<String> = if let Some(g) = vault.entries.get(&group_name) {
        if active_tag == BASE_TAG {
            g.base.keys().cloned().collect()
        } else {
            g.tags
                .get(active_tag)
                .map(|t| t.entries.keys().cloned().collect())
                .unwrap_or_default()
        }
    } else {
        Vec::new()
    };

    let mut initial_content = format!("# envseal edit: group='{group_name}', tag='{active_tag}'\n");
    for key in &existing_keys {
        if let Ok(val) = vault.get_entry(&master_keys.master_dek, Some(&group_name), tag, key) {
            initial_content.push_str(&format!("{key}={}\n", format_env_value(&val)));
        }
    }

    let mut temp = ShredOnDrop(NamedTempFile::new()?);
    temp.0.write_all(initial_content.as_bytes())?;
    temp.0.flush()?;

    let editor_var = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".into()
            } else {
                "nano".into()
            }
        });
    let parts: Vec<&str> = editor_var.split_whitespace().collect();
    let (cmd, args) = parts
        .split_first()
        .ok_or_else(|| anyhow!("EDITOR variable is empty"))?;

    let status = Command::new(cmd)
        .args(args)
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
        eprintln!("No changes made.");
        return Ok(());
    }

    let parsed = parse_env_lines(&updated_content);
    let new_map: BTreeMap<String, String> = parsed.into_iter().collect();
    let new_keys: HashSet<&str> = new_map.keys().map(String::as_str).collect();

    for key in &existing_keys {
        if !new_keys.contains(key.as_str()) {
            vault.remove_entry(&master_keys.signing_key, Some(&group_name), tag, Some(key))?;
        }
    }

    for (key, val) in new_map {
        vault.set_entry(&master_keys, Some(&group_name), tag, &key, &val)?;
    }

    vault.save()?;
    eprintln!("vault updated successfully!!");
    Ok(())
}

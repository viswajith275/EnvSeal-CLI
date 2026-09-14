use crate::utils::parse_env_lines;
use crate::utils::{unlock, vault::Vault};
use anyhow::{Context, Result};
use std::fs;
use std::io::{stdin, Read};

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
        stdin().read_to_string(&mut buf)?;
        buf
    } else {
        fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read import file '{}'", file_path))?
    };
    let mut vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, Some("import"), allow_env)?;
    let mut imported = 0;

    for (key, val) in parse_env_lines(&raw) {
        vault.set_entry(&master_keys, group, tag, &key, &val)?;
        imported += 1;
    }

    vault.save()?;
    eprintln!("successfully imported {imported} variable(s).");
    Ok(())
}

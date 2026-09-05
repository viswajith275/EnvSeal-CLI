use crate::utils::{resolve, vault::Vault};
use anyhow::{Context, Result};
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn cmd_export(
    group: Option<&str>,
    tag: Option<&str>,
    keys: Vec<&str>,
    token: Option<&str>,
    global: bool,
    pref: Option<&str>,
    output_path: &Path,
    allow_env: bool,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let group_name = vault.resolve_group_name(group)?;
    let location = if vault.is_local() { "local" } else { "global" };

    let target = match tag {
        Some(t) => format!("tag '{t}' inside group '{group_name}'"),
        None => format!("group '{group_name}'"),
    };

    if keys.is_empty() {
        eprintln!("exporting variable(s) from {target} {location} seal...");
    } else {
        eprintln!("exporting variable(s) {keys:?} from {target} {location} seal...");
    }

    let token_str = resolve::load_token(token)?;
    let mut decrypted_envs =
        resolve::resolve_environment(&vault, group, tag, token_str.as_deref(), allow_env)?;

    if !keys.is_empty() {
        for &key in &keys {
            if !decrypted_envs.contains_key(key) {
                eprintln!(
                    "Warning: '{key}' was not found in the vault, or the provided token lacks permission to decrypt it. Skipping..."
                );
            }
        }
        let requested: HashSet<&str> = keys.into_iter().collect();
        decrypted_envs.retain(|k, _| requested.contains(k.as_str()));
    }

    let mut buffer = String::new();
    for (key, value) in &decrypted_envs {
        buffer.push_str(key);
        buffer.push('=');
        buffer.push_str(&format_env_value(value));
        buffer.push('\n');
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(output_path)
        .with_context(|| format!("Failed to open export file '{}'", output_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(output_path, fs::Permissions::from_mode(0o600));
    }

    file.write_all(buffer.as_bytes())
        .with_context(|| format!("Failed to write export file '{}'", output_path.display()))?;

    eprintln!(
        "Successfully exported {} variable(s) to '{}'",
        decrypted_envs.len(),
        output_path.display()
    );

    Ok(())
}

fn format_env_value(value: &str) -> Cow<'_, str> {
    if value.chars().any(|c| {
        matches!(
            c,
            ' ' | '\t' | '\n' | '\r' | '"' | '\'' | '#' | '$' | '`' | '\\'
        )
    }) {
        Cow::Owned(format!("'{}'", value.replace('\'', "'\\''")))
    } else {
        Cow::Borrowed(value)
    }
}

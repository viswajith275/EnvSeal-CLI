use crate::utils::{resolve, vault::Vault};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub fn cmd_export(
    group: Option<&str>,
    tag: Option<&str>,
    keys: Vec<&str>,
    token_file: Option<&PathBuf>,
    global: bool,
    pref: Option<&str>,
    output_path: &PathBuf,
    allow_env: bool,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let group_name = vault.resolve_group_name(group)?;

    let location_label = if vault.is_local() { "local" } else { "global" };
    let message = if let Some(t) = tag {
        match keys.is_empty() {
            true => format!(
                "exporting variable(s) from tag '{}' inside group '{}' {} seal...",
                t, group_name, location_label
            ),
            false => format!(
                "exporting variable(s) '{:?}' from tag '{}' inside group '{}' {} seal...",
                keys, t, group_name, location_label
            ),
        }
    } else {
        format!(
            "exporting variable(s) from group '{}' {} seal...",
            group_name, location_label
        )
    };

    eprintln!("{}", message);

    let mut decrypted_envs = resolve::resolve_secrets(&vault, group, tag, token_file, allow_env)?;

    if !keys.is_empty() {
        let requested_set: HashSet<&str> = keys.iter().copied().collect();
        decrypted_envs.retain(|k, _| requested_set.contains(k.as_str()));

        for key in &keys {
            if !decrypted_envs.contains_key(*key) {
                eprintln!(
                        "Warning: '{}' was not found in the vault, or the provided token lacks permission to decrypt it. Skipping...",
                        key
                    );
            }
        }
    }

    let mut sorted_envs: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    for (key, value) in decrypted_envs {
        sorted_envs.insert(key, value);
    }

    let mut buffer = String::new();
    for (key, value) in &sorted_envs {
        buffer.push_str(&format!("{key}={}\n", format_env_value(value.as_str())));
    }

    // write file natively to disk
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(output_path).with_context(|| {
        format!(
            "Failed to open export file '{}' with restricted permissions",
            output_path.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(output_path, fs::Permissions::from_mode(0o600));
    }

    file.write_all(buffer.as_bytes()).with_context(|| {
        format!(
            "Failed to write exported environment variables to '{}'",
            output_path.display()
        )
    })?;

    eprintln!(
        "Successfully exported {} variable(s) to '{}'",
        sorted_envs.len(),
        output_path.display()
    );

    Ok(())
}

fn format_env_value(value: &str) -> String {
    if value.contains('\n')
        || value.contains(' ')
        || value.contains('"')
        || value.contains('\'')
        || value.contains('#')
        || value.contains('$')
        || value.contains('`')
    {
        format!("'{}'", value.replace('\'', "'\\''"))
    } else {
        value.to_string()
    }
}

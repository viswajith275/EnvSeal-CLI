use std::{
    fs::OpenOptions,
    io::{IsTerminal, Write},
    path::Path,
};

use crate::utils::{
    resolve,
    vault::{DecryptedValue, Vault},
};
use anyhow::Result;

pub fn cmd_get(
    group: Option<&str>,
    tag: Option<&str>,
    key: &str,
    token: Option<&str>,
    global: bool,
    pref: Option<&str>,
    out_file: Option<&Path>,
    allow_env: bool,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let token_str = resolve::load_token(token)?;
    let auto_tag = resolve::auto_tag(&vault, group, tag);
    let mut decrypted_envs = resolve::resolve_environment(
        &vault,
        group,
        auto_tag.as_deref(),
        token_str.as_deref(),
        allow_env,
        None,
    )?;

    match decrypted_envs.remove(key) {
        Some(DecryptedValue::Text(val)) => {
            println!("{}: {}", key, val.as_str());
        }
        Some(DecryptedValue::File {
            env_name,
            bytes,
            file_name,
            file_mode,
        }) => {
            if let Some(out_path) = out_file {
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    let mode = file_mode.unwrap_or(0o600);
                    opts.mode(mode);
                }
                let mut f = opts.open(out_path)?;
                f.write_all(&bytes)?;
                eprintln!(
                    "Extracted file secret '{key}' (${env_name}) to '{}'",
                    out_path.display()
                );
            } else if std::io::stdout().is_terminal() {
                let name_info = file_name
                    .as_deref()
                    .map(|n| format!(" [file: {n}]"))
                    .unwrap_or_default();
                eprintln!(
                    "File secret '{key}' mapped to env '${env_name}'{name_info} ({} bytes)",
                    bytes.len()
                );
                eprintln!("Use '-o [PATH]' to write to disk or pipe stdout");
            } else {
                std::io::stdout().write_all(&bytes)?;
            }
        }
        None => anyhow::bail!(
            "No entry named '{key}' found, or the provided token lacks permission to decrypt it!"
        ),
    }

    Ok(())
}

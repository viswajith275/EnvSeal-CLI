use crate::utils::{unlock, vault::Vault};
use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

pub fn cmd_token(
    group: Option<&str>,
    tag: Option<&str>,
    name: &str,
    desc: Option<&str>,
    out_file: Option<&PathBuf>,
    allowed_keys: Vec<String>,
    ttl_seconds: Option<u64>,
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    let master_keys = unlock::sudo_unlock(&vault, Some("token"), allow_env)?;

    let filter = (!allowed_keys.is_empty()).then_some(allowed_keys.as_slice());

    let token_string = vault.create_token(
        &master_keys.signing_key,
        &master_keys.master_dek,
        group,
        tag,
        name,
        ttl_seconds,
        desc,
        filter,
    )?;

    if let Some(path) = out_file {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options
            .open(path)
            .with_context(|| format!("Failed to open token output file '{}'", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }

        file.write_all(token_string.as_bytes())
            .with_context(|| format!("Failed to write token to '{}'", path.display()))?;

        #[cfg(unix)]
        eprintln!(
            "Token successfully written to '{}' (permissions 0600).",
            path.display()
        );

        #[cfg(windows)]
        eprintln!(
            "Token successfully written to '{}'. Ensure folder permissions are restricted.",
            path.display()
        );
    } else {
        eprintln!("Token generated successfully. Pass via ENVSEAL_TOKEN or --token\n");
        println!("{token_string}");
    }

    Ok(())
}

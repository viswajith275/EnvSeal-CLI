use crate::utils::{
    unlock,
    vault::{Vault, BASE_TAG},
};
use anyhow::Result;
use fs2::FileExt;
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
    let master_keys = unlock::sudo_unlock(&vault, None, allow_env)?;

    let active_tag = tag.unwrap_or(BASE_TAG);
    let tag_dek = if active_tag != BASE_TAG && vault.is_tag_protected(group, Some(active_tag))? {
        Some(unlock::sudo_unlock_tag(
            &vault, group, active_tag, None, allow_env,
        )?)
    } else {
        None
    };

    let filter = if allowed_keys.is_empty() {
        None
    } else {
        Some(allowed_keys.as_slice())
    };

    // Delegates scope creation, base inheritance, tag overriding, and signing
    let token_string = vault.create_token(
        &master_keys.signing_key,
        &master_keys.master_dek,
        group,
        tag,
        tag_dek.as_deref(),
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

        let file = options.open(path)?;
        file.lock_exclusive()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }

        let mut writer = std::io::BufWriter::new(&file);
        writer.write_all(token_string.as_bytes())?;
        writer.flush()?;

        let _ = file.unlock();

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
        eprintln!("Token generated successfully. Pass via ENVSEAL_TOKEN or --token-file\n");
        println!("{token_string}");
    }

    Ok(())
}

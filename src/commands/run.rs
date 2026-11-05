use crate::cli::OverrideArgs;
use crate::utils::vault::DecryptedValue;
use crate::utils::{git, resolve, vault::Vault, ShredOnDrop};
use anyhow::{Context, Result};
use std::io::Write;
use std::process::Command;

pub fn cmd_run(
    group: Option<&str>,
    tag: Option<&str>,
    token: Option<&str>,
    command: &[String],
    global: bool,
    pref: Option<&str>,
    allow_env: bool,
    clear: bool,
    overrides: &OverrideArgs,
) -> Result<u8> {
    if command.is_empty() {
        anyhow::bail!("No command specified to run.");
    }

    let _ = git::auto_sync_repo_git_conf();

    let token_str = resolve::load_token(token)?;
    let vault = Vault::load(global, pref)?;

    let auto_tag = resolve::auto_tag(&vault, group, tag);

    let override_val = resolve::OverrideVals {
        keys: &overrides.r#override,
        with_global: overrides.with_global,
        global_group: overrides.global_group.as_deref(),
        global_tag: overrides.global_tag.as_deref(),
    };

    let env_vars = resolve::resolve_environment(
        &vault,
        group,
        auto_tag.as_deref(),
        token_str.as_deref(),
        allow_env,
        Some(&override_val),
    )?;

    let mut child = Command::new(&command[0]);

    if clear {
        child.env_clear();
    }

    child.args(&command[1..]);

    let mut active_temp_files = Vec::new();

    for (key, dec_val) in env_vars {
        match dec_val {
            DecryptedValue::Text(val) => {
                child.env(key, val.as_str()); // Normal insertion
            }
            DecryptedValue::File {
                env_name,
                bytes,
                file_name,
                file_mode,
            } => {
                let suffix = file_name
                    .as_deref()
                    .and_then(|name| std::path::Path::new(name).extension())
                    .map(|ext| format!(".{}", ext.to_string_lossy()))
                    .unwrap_or_default();

                let mut builder = tempfile::Builder::new();
                builder.prefix(".envseal_");
                if !suffix.is_empty() {
                    builder.suffix(&suffix);
                }

                let mut temp = builder
                    .tempfile()
                    .context("Failed to allocate secure temporary file for secret")?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = file_mode.unwrap_or(0o600);
                    let _ = std::fs::set_permissions(
                        temp.path(),
                        std::fs::Permissions::from_mode(mode),
                    );
                }

                temp.write_all(&bytes)
                    .context("Failed to write decrypted file content to temporary secret file")?;
                temp.flush()?;

                child.env(env_name, temp.path()); // Path insertion
                active_temp_files.push(ShredOnDrop(temp));
            }
        }
    }

    let status = child
        .status()
        .with_context(|| format!("Failed to execute command '{}'", command[0]))?;

    drop(active_temp_files);

    #[cfg(unix)]
    let exit_code = {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = status.code() {
            code as u8
        } else if let Some(sig) = status.signal() {
            (128 + sig) as u8
        } else {
            1
        }
    };
    #[cfg(not(unix))]
    let exit_code = status.code().unwrap_or(1) as u8;

    Ok(exit_code)
}

use crate::utils::envelope;
use crate::utils::git::sync_repo_git_conf;
use crate::utils::vault::Vault;
use anyhow::Result;

pub fn cmd_init(
    local: bool,
    global: bool,
    pref: Option<&str>,
    init_git: bool,
    recipient: Option<String>,
) -> Result<()> {
    if local && global {
        anyhow::bail!("Cannot specify both --local and --global flags!");
    }

    let target_path = Vault::resolve_path(local, global, pref)?;

    if target_path.exists() {
        anyhow::bail!("Seal already exists at {}", target_path.display());
    }

    eprintln!(
        "
 /$$$$$$$$                       /$$$$$$                      /$$
| $$_____/                      /$$__  $$                    | $$
| $$       /$$$$$$$  /$$    /$$| $$  \\__/  /$$$$$$   /$$$$$$ | $$
| $$$$$   | $$__  $$|  $$  /$$/|  $$$$$$  /$$__  $$ |____  $$| $$
| $$__/   | $$  \\ $$ \\  $$/$$/  \\____  $$| $$$$$$$$  /$$$$$$$| $$
| $$      | $$  | $$  \\  $$$/   /$$  \\ $$| $$_____/ /$$__  $$| $$
| $$$$$$$$| $$  | $$   \\  $/   |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$
|________/|__/  |__/    \\_/     \\______/  \\_______/ \\_______/|__/

                                                                   "
    );

    let target_recipient = match recipient {
        Some(r) => r,
        None => envelope::get_or_create_default_recipient()?,
    };

    Vault::init(vec![target_recipient.clone()], local, global, pref)?;
    let target_path = Vault::resolve_path(local, global, pref)?;
    eprintln!(
        "Vault initialized at '{}' with recipient: {}",
        target_path.display(),
        target_recipient
    );

    if !global {
        let _ = sync_repo_git_conf(init_git);
    }
    Ok(())
}

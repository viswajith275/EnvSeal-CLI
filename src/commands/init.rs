use crate::utils::git::sync_repo_git_conf;
use crate::utils::unlock;
use crate::utils::vault::Vault;
use anyhow::Result;

pub fn cmd_init(local: bool, global: bool, pref: Option<&str>, init_git: bool) -> Result<()> {
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

    let password = unlock::prompt_with_fallback("master password for envseal: ")?;
    let confirm = unlock::prompt_with_fallback("confirm master password: ")?;
    if *password != *confirm {
        anyhow::bail!("Passwords did not match!!");
    }

    Vault::init(&password, local, global, pref)?;
    eprintln!("seal created at {}", target_path.display());

    if !global {
        if let Err(e) = sync_repo_git_conf(init_git) {
            eprintln!("Warning: Failed to configure Git integration: {e}");
        }
    }
    Ok(())
}

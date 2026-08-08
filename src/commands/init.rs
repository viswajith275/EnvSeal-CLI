use crate::utils::vault::Vault;
use anyhow::Result;
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_init(local: bool, global: bool) -> Result<()> {
    if local && global {
        anyhow::bail!("Cannot specify both --local and --global flags!");
    }

    let target_path = Vault::resolve_path(local, global)?;

    if target_path.exists() {
        anyhow::bail!("Seal already exists at {}", target_path.display());
    }

    eprintln!(
        "\n{}\n",
        r#"
 /$$$$$$$$                       /$$$$$$                      /$$
| $$_____/                      /$$__  $$                    | $$
| $$       /$$$$$$$  /$$    /$$| $$  \__/  /$$$$$$   /$$$$$$ | $$
| $$$$$   | $$__  $$|  $$  /$$/|  $$$$$$  /$$__  $$ |____  $$| $$
| $$__/   | $$  \ $$ \  $$/$$/  \____  $$| $$$$$$$$  /$$$$$$$| $$
| $$      | $$  | $$  \  $$$/   /$$  \ $$| $$_____/ /$$__  $$| $$
| $$$$$$$$| $$  | $$   \  $/   |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$
|________/|__/  |__/    \_/     \______/  \_______/ \_______/|__/

                                                                   "#
    );

    let password = Zeroizing::new(prompt_password("master password for envseal: ")?);
    let confirm = Zeroizing::new(prompt_password("confirm master password: ")?);
    if *password != *confirm {
        anyhow::bail!("Passwords did not match!!");
    }

    Vault::init(&password, local, global)?;
    eprintln!("seal created at {}", target_path.display());
    Ok(())
}

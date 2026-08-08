use crate::utils::vault::Vault;
use anyhow::Result;
use rpassword::prompt_password;
use zeroize::Zeroizing;

pub fn cmd_init() -> Result<()> {
    if Vault::exists() {
        anyhow::bail!("Seal already exists at {}", Vault::path()?.display());
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

    Vault::init(&password)?;
    eprintln!("seal created at {}", Vault::path()?.display());
    Ok(())
}

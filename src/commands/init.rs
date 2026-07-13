use crate::utils::vault::Vault;
use zeroize::Zeroizing;
use rpassword::prompt_password;
use anyhow::Result;

pub fn cmd_init() -> Result<()> {
    if Vault::exists() {
        anyhow::bail!("vault already exists at {}", Vault::path()?.display());
    }

    eprintln!("\n{}\n", r#"                                 /$$$$$$                              
                                /$$__  $$                             
  /$$$$$$  /$$$$$$$  /$$    /$$| $$  \__//$$   /$$  /$$$$$$$  /$$$$$$ 
 /$$__  $$| $$__  $$|  $$  /$$/| $$$$   | $$  | $$ /$$_____/ /$$__  $$
| $$$$$$$$| $$  \ $$ \  $$/$$/ | $$_/   | $$  | $$|  $$$$$$ | $$$$$$$$
| $$_____/| $$  | $$  \  $$$/  | $$     | $$  | $$ \____  $$| $$_____/
|  $$$$$$$| $$  | $$   \  $/   | $$     |  $$$$$$/ /$$$$$$$/|  $$$$$$$
 \_______/|__/  |__/    \_/    |__/      \______/ |_______/  \_______/
                                                                      
                                                                      
                                                                      "#
            );
 
    let password = Zeroizing::new(prompt_password("Set a master password: ")?);
    let confirm = Zeroizing::new(prompt_password("Confirm master password: ")?);
    if *password != *confirm {
        anyhow::bail!("passwords did not match");
    }
    
    Vault::init(&password)?;
    eprintln!("Vault created at {}", Vault::path()?.display());
    Ok(())
}
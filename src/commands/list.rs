use crate::utils::vault::Vault;
use anyhow::Result;

pub fn cmd_list(group_name: &str) -> Result<()> {
    let vault = Vault::load()?;

    let keys = vault.list_all_keys(group_name);
    let keys = match keys {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    };
    eprintln!("\nStored-Keys-In-{group_name}");
    eprintln!("--------------------");
    for key in keys {
        eprintln!("{key}");
    }
    Ok(())
}

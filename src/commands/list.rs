use crate::utils::{resolve, vault::Vault};
use anyhow::Result;
use std::io::{stdout, IsTerminal};

pub fn cmd_list(
    group: Option<&str>,
    tag: Option<&str>,
    global: bool,
    pref: Option<&str>,
) -> Result<()> {
    let vault = Vault::load(global, pref)?;
    vault.verify_integrity()?;
    let auto_tag = resolve::auto_tag(&vault, group, tag);
    let secrets = vault.list_secrets(group, auto_tag.as_deref())?;
    if stdout().is_terminal() {
        let group_name = vault.resolve_group_name(group)?;
        let header: String = if vault.is_local() {
            match auto_tag.as_deref() {
                Some(t) => format!("# tag: {t} [local]"),
                None => "# [local]".to_string(),
            }
        } else {
            match auto_tag.as_deref() {
                Some(t) => format!("# group: {group_name}, tag: {t} [global]"),
                None => format!("# group: {group_name} [global]"),
            }
        };

        eprintln!("{header}");
    }
    for s in secrets {
        if stdout().is_terminal() {
            if s.is_file {
                println!("{} [file -> ${}]", s.name, s.env_name.unwrap_or_default());
            } else {
                println!("{} [text]", s.name);
            }
        } else {
            println!("{}", s.name);
        }
    }
    Ok(())
}

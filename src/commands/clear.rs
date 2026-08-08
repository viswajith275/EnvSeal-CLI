use crate::utils::{session::SessionManager, vault::Vault};
use anyhow::Result;

pub fn cmd_clear(global: bool, pref: Option<&str>) -> Result<()> {
    let vault = Vault::load(global, pref)?;

    let master_scope = vault.master_scope();
    SessionManager::clear_session(&master_scope)?;

    let mut tag_count = 0;
    for (group_name, group) in &vault.entries {
        for tag_name in group.tags.keys() {
            if let Ok(tag_scope) = vault.tag_scope(Some(group_name), tag_name) {
                let _ = SessionManager::clear_session(&tag_scope);
                tag_count += 1;
            }
        }
    }

    let location = if vault.is_local() { "local" } else { "global" };
    let env_suffix = pref
        .map(|p| format!(" [profile: .{p}.envseal]"))
        .unwrap_or_default();

    eprintln!(
        "Cleared session cache for {location} vault {env_suffix} (master session + {tag_count} tag scope(s))."
    );
    eprintln!("Password authentication will be required for your next operation!!");

    Ok(())
}

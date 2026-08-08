use crate::utils::session::SessionManager;
use crate::utils::unlock::MASTER_SCOPE;
use anyhow::{Ok, Result};

pub fn cmd_clear() -> Result<()> {
    let _ = SessionManager::clear_session(MASTER_SCOPE);

    eprintln!("cleared master password from cache!, master password is required from now on!!");
    Ok(())
}

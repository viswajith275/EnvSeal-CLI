use anyhow::Result;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const SERVICE_NAME: &str = "envseal";
const SESSION_TIMEOUT_SEC: u64 = 600; // 10 minutes

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct SessionData {
    password: String,
    expires_at: u64,
}

pub struct SessionManager;

impl SessionManager {
    /// Scope to diffrentiate between master and protected tag
    fn get_entry(scope: &str) -> Result<Entry> {
        Ok(Entry::new(SERVICE_NAME, scope)?)
    }

    /// Caches the password and sets/resets the 15 minute timer
    pub fn cache_password(scope: &str, password: &str) -> Result<()> {
        let expires_at =
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + SESSION_TIMEOUT_SEC;

        let session = SessionData {
            password: password.to_string(),
            expires_at,
        };

        let entry = Self::get_entry(scope)?;
        entry.set_password(&serde_json::to_string(&session)?)?;
        Ok(())
    }

    /// Removes the cached password
    pub fn clear_session(scope: &str) -> Result<()> {
        let _ = Self::get_entry(scope)?.delete_credential();
        Ok(())
    }

    /// Retrieves the password if it hasn't expired
    pub fn get_active_password(scope: &str) -> Result<Option<String>> {
        let entry = match Self::get_entry(scope) {
            Ok(e) => e,
            Err(_) => return Ok(None), // no keyring
        };

        let serialized = match entry.get_password() {
            Ok(pw) => pw,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(_) => return Ok(None),
        };

        let session: SessionData = match serde_json::from_str(&serialized) {
            Ok(s) => s,
            Err(_) => {
                let _ = Self::clear_session(scope);
                return Ok(None);
            }
        };

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if now > session.expires_at {
            let _ = Self::clear_session(scope);
            Ok(None)
        } else {
            Ok(Some(session.password.clone()))
        }
    }
}

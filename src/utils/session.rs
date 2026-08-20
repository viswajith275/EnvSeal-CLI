use super::crypto;
use anyhow::Result;
use base64::Engine;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SERVICE_NAME: &str = "envseal";
const SESSION_TIMEOUT_SEC: u64 = 600; // 10 minutes

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub enum CachedKeys {
    Master {
        kek: [u8; crypto::KEY_LEN],
        seed: [u8; crypto::KEY_LEN],
    },
    Tag {
        dek: [u8; crypto::KEY_LEN],
    },
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SessionData {
    keys: CachedKeys,
    expires_at: u64,
}

pub struct SessionManager;

impl SessionManager {
    /// Scope to diffrentiate between master and protected tag
    fn get_entry(scope: &str) -> Result<Entry, keyring::Error> {
        Entry::new(SERVICE_NAME, scope)
    }

    /// Caches the keys and sets/resets the 10 minute timer
    pub fn cache_keys(scope: &str, keys: CachedKeys) -> Result<()> {
        let expires_at =
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + SESSION_TIMEOUT_SEC;
        let session = SessionData { keys, expires_at };

        let serialized_bytes = rmp_serde::to_vec(&session)?;
        let serialized = base64::engine::general_purpose::STANDARD.encode(serialized_bytes);

        match Self::get_entry(scope) {
            Ok(entry) => {
                if let Err(e) = entry.set_password(&serialized) {
                    eprintln!("[envseal] Warning: Failed to write to OS keyring: {e}, Session will not be cached!!");
                }
            }
            Err(e) => {
                eprintln!("[envseal] Warning: OS keyring unavailable (headless Linux/WSL?): {e}, Proceeding in-memory only.");
            }
        }

        Ok(())
    }

    /// Removes the cached keys
    pub fn clear_session(scope: &str) -> Result<()> {
        if let Ok(entry) = Self::get_entry(scope) {
            let _ = entry.delete_credential();
        }
        Ok(())
    }

    /// Retrieves the keys if it hasn't expired
    pub fn get_active_keys(scope: &str) -> Result<Option<CachedKeys>> {
        let entry = match Self::get_entry(scope) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };

        let encoded = match entry.get_password() {
            Ok(pw) => pw,
            Err(_) => return Ok(None),
        };

        let bytes = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(b) => b,
            Err(_) => {
                let _ = Self::clear_session(scope);
                return Ok(None);
            }
        };

        let mut session: SessionData = match rmp_serde::from_slice(&bytes) {
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
            let valid_keys =
                std::mem::replace(&mut session.keys, CachedKeys::Tag { dek: [0u8; 32] });
            Ok(Some(valid_keys))
        }
    }
}

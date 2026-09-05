use super::crypto;
use anyhow::Result;
use base64::Engine;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SERVICE_NAME: &str = "envseal";
const SESSION_TIMEOUT_SEC: u64 = 600; // 10 minutes

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
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
    fn get_entry(scope: &str) -> Result<Entry, keyring::Error> {
        Entry::new(SERVICE_NAME, scope)
    }

    /// Caches the keys and sets/resets the 10 minute timer
    pub fn cache_keys(scope: &str, keys: CachedKeys) -> Result<()> {
        let expires_at =
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + SESSION_TIMEOUT_SEC;
        let session = SessionData { keys, expires_at };
        let serialized_bytes = Zeroizing::new(serde_json::to_vec(&session)?);
        let serialized = base64::engine::general_purpose::STANDARD.encode(&*serialized_bytes);
        if let Ok(entry) = Self::get_entry(scope) {
            let _ = entry.set_password(&serialized);
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
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if let Ok(entry) = Self::get_entry(scope) {
            if let Ok(encoded) = entry.get_password() {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    let zero_bytes = Zeroizing::new(bytes);
                    if let Ok(mut session) = serde_json::from_slice::<SessionData>(&zero_bytes) {
                        if now <= session.expires_at {
                            let valid_keys = std::mem::replace(
                                &mut session.keys,
                                CachedKeys::Tag { dek: [0u8; 32] },
                            );
                            return Ok(Some(valid_keys));
                        } else {
                            let _ = Self::clear_session(scope);
                            return Ok(None);
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

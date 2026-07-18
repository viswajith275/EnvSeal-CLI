use super::crypto;
use anyhow::{anyhow, Ok, Result};
use base64::Engine;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

const CANARY_PLAINTEXT: &str = "envseal-Encrypted";

#[derive(Serialize, Deserialize)]
pub struct Entry {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
pub struct Group {
    link: PathBuf,
    base: HashMap<String, Entry>,
    tags: HashMap<String, HashMap<String, Entry>>,
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    salt: String,
    canary: Entry,
    link_index: HashMap<PathBuf, String>, // used for fetching group
    entries: HashMap<String, Group>,
}

impl Vault {
    // find config/data directories acording t os
    pub fn path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("dev", "envseal", "envseal")
            .ok_or_else(|| anyhow!("could not determine a config directory for this OS"))?;

        Ok(dirs.config_dir().join("seal-encrypted.json"))
    }

    // check if it directory already exists or not
    pub fn exists() -> bool {
        Self::path().map(|p| p.exists()).unwrap_or(false)
    }

    //  Creates and initiates vault
    pub fn init(password: &str) -> Result<()> {
        let salt = crypto::generate_salt();
        let key = crypto::derive_key(password, &salt)?;
        let (nonce, ciphertext) = crypto::encrypt(&key, CANARY_PLAINTEXT)?;

        let vault = Vault {
            salt: b64_encode(&salt),
            canary: Entry {
                nonce: b64_encode(&nonce),
                ciphertext: b64_encode(&ciphertext),
            },
            link_index: HashMap::new(),
            entries: HashMap::new(),
        };
        vault.save()
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let data = fs::read_to_string(&path)
            .map_err(|_| anyhow!("no seal found — run `envseal init` first"))?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn unlock(&self, password: &str) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>> {
        let salt = b64_decode(&self.salt)?;
        let key = crypto::derive_key(password, &salt)?;

        let nonce = b64_decode(&self.canary.nonce)?;
        let ciphertext = b64_decode(&self.canary.ciphertext)?;
        let plaintext = crypto::decrypt(&key, &nonce, &ciphertext)
            .map_err(|_| anyhow!("wrong Master Password!"))?;

        if plaintext != CANARY_PLAINTEXT {
            return Err(anyhow!("wrong Master Password!"));
        }
        Ok(key)
    }

    pub fn create_group(&mut self, group_name: &str) -> Result<()> {
        self.entries.entry(group_name.to_string()).or_insert(Group {
            link: PathBuf::new(),
            base: HashMap::new(),
            tags: HashMap::new(),
        });
        Ok(())
    }

    pub fn get_current_active_group_name(&self) -> Result<&String> {
        let cur_dir = env::current_dir()?;

        let name = self
            .link_index
            .get(&cur_dir)
            .ok_or_else(|| anyhow!("no group linked to current directory!"))?;
        Ok(name)
    }

    pub fn add_entry(
        &mut self,
        key: &[u8; crypto::KEY_LEN],
        group_name: &Option<String>,
        name: &str,
        value: &str,
    ) -> Result<()> {
        let (nonce, ciphertext) = crypto::encrypt(key, value)?;
        self.entries
            .entry(group_name.to_string())
            .or_default()
            .insert(
                name.to_string(),
                Entry {
                    nonce: b64_encode(&nonce),
                    ciphertext: b64_encode(&ciphertext),
                },
            );
        Ok(())
    }

    pub fn get_entry(
        &self,
        key: &[u8; crypto::KEY_LEN],
        group_name: &str,
        name: &str,
    ) -> Result<String> {
        let group = self
            .entries
            .get(group_name)
            .ok_or_else(|| anyhow!("no group named '{group_name}'"))?;
        let entry = group
            .get(name)
            .ok_or_else(|| anyhow!("no entry named '{name}' in group '{group_name}'"))?;

        let nonce = b64_decode(&entry.nonce)?;
        let ciphertext = b64_decode(&entry.ciphertext)?;
        crypto::decrypt(key, &nonce, &ciphertext)
    }

    pub fn remove_entry(&mut self, group_name: &str, name: &str) -> Result<()> {
        let removed = self
            .entries
            .get_mut(group_name)
            .ok_or_else(|| anyhow!("no group named '{group_name}'"))?;
        let removed = removed.remove(name);

        if removed.is_some() {
            Ok(())
        } else {
            Err(anyhow!("no entry named '{name}' in group '{group_name}'"))
        }
    }

    pub fn remove_group(&mut self, group_name: &str) -> Result<()> {
        if let Some(removed_group) = self.entries.remove(group_name) {
            self.link_index.remove(&removed_group.link);
            Ok(())
        } else {
            Err(anyhow!("no group named '{group_name}'"))
        }
    }

    pub fn list_all_keys(&self, group_name: &str) -> Result<Vec<String>> {
        let group = self
            .entries
            .get(group_name)
            .ok_or_else(|| anyhow!("no group named '{group_name}'"))?;
        let keys = group.keys();
        Ok(keys.cloned().collect())
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

use super::crypto;
use anyhow::{anyhow, Result};
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
        if let Ok(override_path) = std::env::var("ENVSEAL_TEST_PATH") {
            return Ok(PathBuf::from(override_path));
        }
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
        if Self::exists() {
            return Err(anyhow!("Seal already exists! Refusing to overwrite..."));
        }
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
        // loads the file into the struct
        Ok(serde_json::from_str(&data)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // writes the changes in the struct to json file
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

        // checking if the password is correct
        if plaintext != CANARY_PLAINTEXT {
            return Err(anyhow!("wrong Master Password!"));
        }
        Ok(key)
    }

    pub fn link_group(&mut self, group: String) -> Result<()> {
        // Remove existing links
        if let Some(existing_group) = self.entries.get(&group) {
            self.link_index.remove(&existing_group.link);
        }
        // get current path and create an entry if doesnt exist
        let cur_dir = env::current_dir()?;
        let group_entry = self
            .entries
            .entry(group.to_string())
            .or_insert_with(|| Group {
                link: PathBuf::new(),
                base: HashMap::new(),
                tags: HashMap::new(),
            });
        // update entries link part
        group_entry.link = cur_dir.to_path_buf();
        // reflect it to link index hash_map
        self.link_index.insert(cur_dir.to_path_buf(), group);

        Ok(())
    }

    pub fn set_entry(
        &mut self,
        key: &[u8; crypto::KEY_LEN],
        group: &Option<String>,
        tag: &Option<String>,
        name: &str,
        value: &str,
    ) -> Result<()> {
        // fetching current directory and encrypting password
        let cur_dir = env::current_dir()?;
        let (nonce, ciphertext) = crypto::encrypt(key, value)?;

        let group_name = match group {
            Some(name) => name,
            None => self
                .link_index
                .get(&cur_dir)
                .ok_or_else(|| anyhow!("no group linked to current directory!"))?,
        };
        // Creating and fetching the group if the group doesnt exist
        let group_entry = self
            .entries
            .entry(group_name.to_string())
            .or_insert_with(|| Group {
                link: PathBuf::new(),
                base: HashMap::new(),
                tags: HashMap::new(),
            });

        // getting tag (base as default)
        let active_tag = match tag {
            Some(t) => t,
            None => "base",
        };
        if active_tag == "base" {
            group_entry
                .base
                .entry(name.to_string())
                .insert_entry(Entry {
                    nonce: b64_encode(&nonce),
                    ciphertext: b64_encode(&ciphertext),
                });
        } else {
            group_entry
                .tags
                .entry(active_tag.to_string())
                .or_default()
                .insert(
                    name.to_string(),
                    Entry {
                        nonce: b64_encode(&nonce),
                        ciphertext: b64_encode(&ciphertext),
                    },
                );
        }

        Ok(())
    }

    pub fn get_entry(
        &self,
        key: &[u8; crypto::KEY_LEN],
        group: &Option<String>,
        tag: &Option<String>,
        name: &str,
    ) -> Result<String> {
        // fetching group name
        let cur_dir = env::current_dir()?;
        let group_name = match group {
            Some(name) => name,
            None => self
                .link_index
                .get(&cur_dir)
                .ok_or_else(|| anyhow!("no group linked to current directory!"))?,
        };

        // Geting the group entry
        let group_entry = self
            .entries
            .get(&group_name.to_string())
            .ok_or_else(|| anyhow!("no group named '{group_name}'"))?;

        // getting tag (base as default)
        let active_tag = match tag {
            Some(t) => t,
            None => "base",
        };

        let entry: &Entry;

        // finding entry inside base and tag
        if active_tag == "base" {
            entry = group_entry
                .base
                .get(name)
                .ok_or_else(|| anyhow!("no entry named '{name}' in group '{group_name}'"))?;
        } else {
            entry = group_entry
                .tags
                .get(active_tag)
                .ok_or_else(|| anyhow!("no tag named '{active_tag}' in group '{group_name}'"))?
                .get(name)
                .ok_or_else(|| {
                    anyhow!("no entry named '{name} in tag '{active_tag}' in group '{group_name}'")
                })?;
        }

        // decoding and decrypting the value
        let nonce = b64_decode(&entry.nonce)?;
        let ciphertext = b64_decode(&entry.ciphertext)?;

        crypto::decrypt(key, &nonce, &ciphertext)
    }

    pub fn remove_entry(
        &mut self,
        group: &Option<String>,
        tag: &Option<String>,
        name: &Option<String>,
    ) -> Result<()> {
        // get active group name
        let cur_dir = env::current_dir()?;
        let group_name = match group {
            Some(val) => val.as_str(),
            None => self
                .link_index
                .get(&cur_dir)
                .ok_or_else(|| anyhow!("no group linked to current directory!"))?
                .as_str(),
        };

        let active_tag = tag.as_deref().unwrap_or("base");
        let name = name.as_deref().unwrap_or("");

        // remove group if nothing is provided
        if tag.is_none() && name.is_empty() {
            if let Some(removed_group) = self.entries.remove(group_name) {
                self.link_index.remove(&removed_group.link);
                return Ok(());
            } else {
                return Err(anyhow!("no group named '{group_name}'"));
            }
        }

        let group_entry = self
            .entries
            .get_mut(group_name)
            .ok_or_else(|| anyhow!("no group named '{group_name}'"))?;

        // Remove tag
        if name.is_empty() && active_tag != "base" {
            group_entry
                .tags
                .remove(active_tag)
                .ok_or_else(|| anyhow!("no tag named '{active_tag}' in group '{group_name}'"))?;

            return Ok(());
        }

        // Remove a entry inside a specific tag
        if !name.is_empty() && active_tag != "base" {
            group_entry
                .tags
                .get_mut(active_tag)
                .ok_or_else(|| anyhow!("no tag named '{active_tag}' in group '{group_name}'"))?
                .remove(name)
                .ok_or_else(|| {
                    anyhow!("no entry named '{name}' in tag '{active_tag}' in group '{group_name}'")
                })?;

            return Ok(());
        }

        // Remove a entry from the base group
        group_entry
            .base
            .remove(name)
            .ok_or_else(|| anyhow!("no entry named '{name}' in group '{group_name}'"))?;

        Ok(())
    }

    pub fn list_all_keys(
        &self,
        group: &Option<String>,
        tag: &Option<String>,
    ) -> Result<Vec<String>> {
        // getting group name
        let cur_dir = env::current_dir()?;
        let group_name = match group {
            Some(name) => name,
            None => self
                .link_index
                .get(&cur_dir)
                .ok_or_else(|| anyhow!("no group linked to current directory!"))?,
        };

        // Geting the group entry
        let group_entry = self
            .entries
            .get(&group_name.to_string())
            .ok_or_else(|| anyhow!("no group named '{group_name}'"))?;

        // getting tag (base as default)
        let active_tag = match tag {
            Some(t) => t,
            None => "base",
        };

        let keys: Vec<String>;

        // finding entries inside base and tag
        if active_tag == "base" {
            keys = group_entry.base.keys().cloned().collect();
        } else {
            keys = group_entry
                .tags
                .get(active_tag)
                .ok_or_else(|| anyhow!("no tag named '{active_tag}' in group '{group_name}'"))?
                .keys()
                .cloned()
                .collect();
        }

        Ok(keys)
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

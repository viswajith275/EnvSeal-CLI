use super::crypto;
use anyhow::{anyhow, Result};
use base64::Engine;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CANARY_PLAINTEXT: &str = "envseal-Encrypted";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
    pub enc_key: Zeroizing<[u8; crypto::KEY_LEN]>,
    pub hmac_key: Zeroizing<[u8; crypto::HMAC_KEY_LEN]>,
}

#[derive(Serialize, Deserialize)]
pub struct Entry {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
pub struct Tag {
    pub salt: Option<String>,
    pub canary: Option<Entry>,
    pub entries: HashMap<String, Entry>,
}

impl Default for Tag {
    fn default() -> Self {
        Self {
            salt: None,
            canary: None,
            entries: HashMap::new(),
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct Group {
    link: PathBuf,
    base: HashMap<String, Entry>,
    tags: HashMap<String, Tag>,
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    salt: String,
    canary: Entry,
    link_index: HashMap<PathBuf, String>,
    // used for fetching group
    entries: HashMap<String, Group>,
    #[serde(default)]
    hmac: String,
}

// Canonical data structures used for hmac
#[derive(Serialize)]
struct CanonicalEntry<'a> {
    nonce: &'a str,
    ciphertext: &'a str,
}

#[derive(Serialize)]
struct CanonicalTag<'a> {
    salt: Option<&'a str>,
    canary: Option<CanonicalEntry<'a>>,
    entries: BTreeMap<&'a str, CanonicalEntry<'a>>,
}

#[derive(Serialize)]
struct CanonicalGroup<'a> {
    link: &'a PathBuf,
    base: BTreeMap<&'a str, CanonicalEntry<'a>>,
    tags: BTreeMap<&'a str, CanonicalTag<'a>>,
}

#[derive(Serialize)]
struct CanonicalVault<'a> {
    salt: &'a str,
    canary: CanonicalEntry<'a>,
    link_index: BTreeMap<&'a PathBuf, &'a str>,
    entries: BTreeMap<&'a str, CanonicalGroup<'a>>,
}

impl Vault {
    // Turns the canonical vault into signable bytes
    fn signable_bytes(&self) -> Result<Vec<u8>> {
        // Reads the vault into canonical structure
        let entries: BTreeMap<&str, CanonicalGroup> = self
            .entries
            .iter()
            .map(|(name, group)| {
                let base: BTreeMap<&str, CanonicalEntry> = group
                    .base
                    .iter()
                    .map(|(k, e)| {
                        (
                            k.as_str(),
                            CanonicalEntry {
                                nonce: &e.nonce,
                                ciphertext: &e.ciphertext,
                            },
                        )
                    })
                    .collect();

                let tags: BTreeMap<&str, CanonicalTag> = group
                    .tags
                    .iter()
                    .map(|(tag_name, tag)| {
                        let inner_entries: BTreeMap<&str, CanonicalEntry> = tag
                            .entries
                            .iter()
                            .map(|(k, e)| {
                                (
                                    k.as_str(),
                                    CanonicalEntry {
                                        nonce: &e.nonce,
                                        ciphertext: &e.ciphertext,
                                    },
                                )
                            })
                            .collect();

                        let canary = tag.canary.as_ref().map(|c| CanonicalEntry {
                            nonce: &c.nonce,
                            ciphertext: &c.ciphertext,
                        });

                        (
                            tag_name.as_str(),
                            CanonicalTag {
                                salt: tag.salt.as_deref(),
                                canary,
                                entries: inner_entries,
                            },
                        )
                    })
                    .collect();

                (
                    name.as_str(),
                    CanonicalGroup {
                        link: &group.link,
                        base,
                        tags,
                    },
                )
            })
            .collect();

        let link_index: BTreeMap<&PathBuf, &str> = self
            .link_index
            .iter()
            .map(|(k, v)| (k, v.as_str()))
            .collect();

        let canon = CanonicalVault {
            salt: &self.salt,
            canary: CanonicalEntry {
                nonce: &self.canary.nonce,
                ciphertext: &self.canary.ciphertext,
            },
            link_index,
            entries,
        };
        Ok(serde_json::to_vec(&canon)?)
    }

    // computes and updated hmac
    pub fn seal_integrity(&mut self, hmac_key: &[u8; crypto::HMAC_KEY_LEN]) -> Result<()> {
        let bytes = self.signable_bytes()?;
        let tag = crypto::compute_hmac(hmac_key, &bytes);
        self.hmac = b64_encode(&tag);
        Ok(())
    }

    // verifies if the seal has been tampered with by checking hmac
    pub fn verify_integrity(&self, hmac_key: &[u8; crypto::HMAC_KEY_LEN]) -> Result<()> {
        let stored = self.hmac.as_ref();
        let bytes = self.signable_bytes()?;
        let tag = b64_decode(&stored)?;
        if !crypto::verify_hmac(hmac_key, &bytes, &tag) {
            return Err(anyhow!("SEAL TAMPERED: HMAC verification failed!"));
        }
        Ok(())
    }

    // find config/data directories acording to os
    pub fn path() -> Result<PathBuf> {
        if let Ok(override_path) = std::env::var("ENVSEAL_TEST_PATH") {
            return Ok(PathBuf::from(override_path));
        }
        let dirs = ProjectDirs::from("dev", "envseal", "envseal").ok_or_else(|| {
            anyhow!("Could not determine a config directory for this OS!! (Change your OS!!!)")
        })?;
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
        let (enc_key, hmac_key) = crypto::derive_keys(password, &salt)?;
        let (nonce, ciphertext) = crypto::encrypt(&enc_key, CANARY_PLAINTEXT)?;

        let mut vault = Vault {
            salt: b64_encode(&salt),
            canary: Entry {
                nonce: b64_encode(&nonce),
                ciphertext: b64_encode(&ciphertext),
            },
            link_index: HashMap::new(),
            entries: HashMap::new(),
            hmac: String::new(),
        };

        vault.seal_integrity(&hmac_key)?;
        vault.save()
    }

    // loads json to structures
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let data = fs::read_to_string(&path)
            .map_err(|_| anyhow!("No seal found — run `envseal init` first!!"))?;
        // loads the file into the struct
        Ok(serde_json::from_str(&data)?)
    }

    // saves the changed structure into json
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // writes the changes in the struct to json file
        fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    fn resolve_group_name(&self, group: Option<&str>) -> Result<String> {
        if let Some(name) = group {
            Ok(name.to_string())
        } else {
            let cur_dir = env::current_dir()?;
            let name = self
                .link_index
                .get(&cur_dir)
                .ok_or_else(|| anyhow!("No group linked to current directory!!"))?;
            Ok(name.to_string())
        }
    }

    // unloack protected tags
    fn unlock_tag_key(tag: &Tag, password: &str) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>> {
        let salt_str = tag
            .salt
            .as_ref()
            .ok_or_else(|| anyhow!("Tag is not protected!!"))?;
        let canary = tag
            .canary
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupted tag: missing canary!!"))?;

        let salt = b64_decode(salt_str)?;
        let enc_key = crypto::derive_key(&password, &salt)?;

        let nonce = b64_decode(&canary.nonce)?;
        let ciphertext = b64_decode(&canary.ciphertext)?;
        let plaintext = crypto::decrypt(&enc_key, &nonce, &ciphertext)
            .map_err(|_| anyhow!("Wrong Tag Password!!"))?;

        if plaintext != CANARY_PLAINTEXT {
            return Err(anyhow!("Wrong Tag Password!!"));
        }

        Ok(enc_key)
    }

    // unlock master key and hmac key
    pub fn unlock(&self, password: &str) -> Result<VaultKeys> {
        let salt = b64_decode(&self.salt)?;
        let (enc_key, hmac_key) = crypto::derive_keys(password, &salt)?;

        let nonce = b64_decode(&self.canary.nonce)?;
        let ciphertext = b64_decode(&self.canary.ciphertext)?;
        let plaintext = crypto::decrypt(&enc_key, &nonce, &ciphertext)
            .map_err(|_| anyhow!("Wrong Master Password!"))?;

        // checking if the password is correct
        if plaintext != CANARY_PLAINTEXT {
            return Err(anyhow!("Wrong Master Password!"));
        }

        self.verify_integrity(&hmac_key)?;

        Ok(VaultKeys {
            enc_key: enc_key,
            hmac_key: hmac_key,
        })
    }

    // link group to current directory
    pub fn link_group(&mut self, hmac_key: &[u8; crypto::HMAC_KEY_LEN], group: &str) -> Result<()> {
        // Remove existing links
        if let Some(existing_group) = self.entries.get(group) {
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
        self.link_index
            .insert(cur_dir.to_path_buf(), group.to_string());

        self.seal_integrity(hmac_key)?;
        Ok(())
    }

    pub fn create_protected_tag(
        &mut self,
        hmac_key: &[u8; crypto::HMAC_KEY_LEN],
        group: Option<&str>,
        tag: &str,
        tag_password: &str,
    ) -> Result<()> {
        if tag == "base" {
            return Err(anyhow!(
                    "Cannot create a tag named 'base'. This is a reserved keyword for the default space!"
                ));
        }

        let group_name = self.resolve_group_name(group)?;

        let group_entry = self
            .entries
            .entry(group_name.clone())
            .or_insert_with(|| Group {
                link: PathBuf::new(),
                base: HashMap::new(),
                tags: HashMap::new(),
            });

        if group_entry.tags.contains_key(tag) {
            return Err(anyhow!(
                "Tag '{tag}' already exists in group '{group_name}'!"
            ));
        }

        let salt = crypto::generate_salt();
        let enc_key = crypto::derive_key(tag_password, &salt)?;
        let (nonce, ciphertext) = crypto::encrypt(&enc_key, CANARY_PLAINTEXT)?;

        group_entry.tags.insert(
            tag.to_string(),
            Tag {
                salt: Some(b64_encode(&salt)),
                canary: Some(Entry {
                    nonce: b64_encode(&nonce),
                    ciphertext: b64_encode(&ciphertext),
                }),
                entries: HashMap::new(),
            },
        );

        self.seal_integrity(hmac_key)?;
        Ok(())
    }

    // Check if a tag is protected or not
    pub fn is_tag_protected(&self, group: Option<&str>, tag: Option<&str>) -> Result<bool> {
        let tag = match tag {
            Some(val) => val,
            None => return Ok(false),
        };
        if tag == "base" {
            return Ok(false);
        }

        let group_name = self.resolve_group_name(group)?;

        let group_entry = match self.entries.get(&group_name) {
            Some(g) => g,
            None => return Ok(false),
        };

        match group_entry.tags.get(tag) {
            Some(t) => Ok(t.salt.is_some()),
            None => Ok(false),
        }
    }

    // set entry into group/tag
    pub fn set_entry(
        &mut self,
        keys: &VaultKeys,
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
        value: &str,
        tag_password: Option<&str>,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;

        let group_entry = self.entries.entry(group_name).or_insert_with(|| Group {
            link: PathBuf::new(),
            base: HashMap::new(),
            tags: HashMap::new(),
        });

        let active_tag = tag.unwrap_or("base");

        if active_tag == "base" {
            // Base group uses master key
            let (nonce, ciphertext) = crypto::encrypt(&keys.enc_key, value)?;
            group_entry.base.insert(
                name.to_string(),
                Entry {
                    nonce: b64_encode(&nonce),
                    ciphertext: b64_encode(&ciphertext),
                },
            );
        } else {
            let tag_entry = group_entry.tags.entry(active_tag.to_string()).or_default();

            let actually_protected = tag_entry.salt.is_some();

            let (nonce, ciphertext) = if actually_protected {
                let password = tag_password.ok_or_else(|| {
                    anyhow!("Tag '{active_tag}' is protected! Password required.")
                })?;

                let enc_key = Self::unlock_tag_key(tag_entry, password)?;
                crypto::encrypt(&enc_key, value)?
            } else {
                crypto::encrypt(&keys.enc_key, value)?
            };

            tag_entry.entries.insert(
                name.to_string(),
                Entry {
                    nonce: b64_encode(&nonce),
                    ciphertext: b64_encode(&ciphertext),
                },
            );
        }

        self.seal_integrity(&keys.hmac_key)?;
        Ok(())
    }

    pub fn get_entry(
        &self,
        key: &[u8; crypto::KEY_LEN],
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
        tag_password: Option<&str>,
    ) -> Result<Zeroizing<String>> {
        let group_name = self.resolve_group_name(group)?;

        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'!!"))?;

        let active_tag = tag.unwrap_or("base");

        if active_tag == "base" {
            let entry = group_entry
                .base
                .get(name)
                .ok_or_else(|| anyhow!("No entry named '{name}' in group '{group_name}'!!"))?;

            let nonce = b64_decode(&entry.nonce)?;
            let ciphertext = b64_decode(&entry.ciphertext)?;
            let plaintext = crypto::decrypt(&key, &nonce, &ciphertext)?;

            return Ok(Zeroizing::new(plaintext));
        }

        let tag_entry = group_entry
            .tags
            .get(active_tag)
            .ok_or_else(|| anyhow!("No tag named '{active_tag}' in group '{group_name}'!!"))?;

        let actually_protected = tag_entry.salt.is_some();

        let entry = tag_entry.entries.get(name).ok_or_else(|| {
            anyhow!("No entry '{name}' in tag '{active_tag}' in '{group_name}'!!")
        })?;

        let enc_key = if actually_protected {
            let password =
                tag_password.ok_or_else(|| anyhow!("Password required for tag '{active_tag}'!"))?;
            Self::unlock_tag_key(tag_entry, password)?
        } else {
            Zeroizing::new(*key)
        };

        let nonce = b64_decode(&entry.nonce)?;
        let ciphertext = b64_decode(&entry.ciphertext)?;

        let plaintext = crypto::decrypt(&enc_key, &nonce, &ciphertext)?;

        Ok(Zeroizing::new(plaintext))
    }

    pub fn remove_entry(
        &mut self,
        hmac_key: &[u8; crypto::HMAC_KEY_LEN],
        group: Option<&str>,
        tag: Option<&str>,
        name: Option<&str>,
        tag_password: Option<&str>,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;

        let active_tag = tag.as_deref().unwrap_or("base");
        let name_str = name.as_deref().unwrap_or("");

        // Remove an entire group (when no tag or name is provided)
        if tag.is_none() && name_str.is_empty() {
            if let Some(removed_group) = self.entries.remove(&group_name) {
                self.link_index.remove(&removed_group.link);
                self.seal_integrity(hmac_key)?;
                return Ok(());
            } else {
                return Err(anyhow!("No group named '{group_name}'!!"));
            }
        }

        let group_entry = self
            .entries
            .get_mut(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'!!"))?;

        // Validation checks
        if active_tag == "base" {
            // Reject attempting to remove the whole "base" tag
            if name_str.is_empty() {
                return Err(anyhow!(
                        "Cannot remove the reserved 'base' tag entirely. You can only remove individual entries or the entire group!!"
                    ));
            }
        } else {
            let tag_ref = group_entry
                .tags
                .get(active_tag)
                .ok_or_else(|| anyhow!("No tag named '{active_tag}' in group '{group_name}'!!"))?;

            if tag_ref.salt.is_some() {
                let password = tag_password.ok_or_else(|| {
                    anyhow!("Tag '{active_tag}' is protected! Password required to modify it.")
                })?;

                let _ = Self::unlock_tag_key(tag_ref, password)?;
            }
        }

        // Remove a whole tag from group (excluding 'base')
        if name_str.is_empty() && active_tag != "base" {
            group_entry.tags.remove(active_tag);
            self.seal_integrity(hmac_key)?;
            return Ok(());
        }

        // Remove an entry inside a tag
        if !name_str.is_empty() && active_tag != "base" {
            let tag_entry = group_entry.tags.get_mut(active_tag).unwrap();

            tag_entry.entries.remove(name_str).ok_or_else(|| {
                anyhow!(
                    "No entry named '{name_str}' in tag '{active_tag}' in group '{group_name}'!!"
                )
            })?;

            self.seal_integrity(hmac_key)?;
            return Ok(());
        }

        // Remove an entry from the base group
        if active_tag == "base" && !name_str.is_empty() {
            group_entry
                .base
                .remove(name_str)
                .ok_or_else(|| anyhow!("No entry named '{name_str}' in group '{group_name}'!!"))?;

            self.seal_integrity(hmac_key)?;
        }

        Ok(())
    }

    pub fn list_all_keys(&self, group: Option<&str>, tag: Option<&str>) -> Result<Vec<String>> {
        let group_name = self.resolve_group_name(group)?;

        // Geting the group entry
        let group_entry = self
            .entries
            .get(&group_name.to_string())
            .ok_or_else(|| anyhow!("No group named '{group_name}'!!"))?;

        // getting tag (base as default)
        let active_tag = tag.unwrap_or("base");

        let keys: Vec<String>;

        // finding entries inside base and tag
        if active_tag == "base" {
            keys = group_entry.base.keys().cloned().collect();
        } else {
            keys = group_entry
                .tags
                .get(active_tag)
                .ok_or_else(|| anyhow!("No tag named '{active_tag}' in group '{group_name}'!!"))?
                .entries
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

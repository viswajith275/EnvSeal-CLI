use super::crypto;
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fmt;
use std::fs;
use std::hash::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use tempfile::NamedTempFile;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const CANARY_PLAINTEXT: &str = "envseal-Encrypted";
pub const BASE_TAG: &str = "base";
const LOCAL_GROUP_NAME: &str = "project";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
    pub enc_key: Zeroizing<[u8; crypto::KEY_LEN]>,
    pub hmac_key: Zeroizing<[u8; crypto::HMAC_KEY_LEN]>,
}

impl fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultKeys")
            .field("enc_key", &"[REDACTED]")
            .field("hmac_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Entry {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Tag {
    pub salt: Option<String>,
    pub canary: Option<Entry>,
    pub entries: HashMap<String, Entry>,
}

#[derive(Serialize, Deserialize)]
pub struct Group {
    link: PathBuf,
    base: HashMap<String, Entry>,
    pub tags: HashMap<String, Tag>,
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    salt: String,
    canary: Entry,
    link_index: HashMap<PathBuf, String>,
    // used for fetching group
    pub entries: HashMap<String, Group>,
    #[serde(default)]
    hmac: String,
    #[serde(skip)]
    file_path: Option<PathBuf>,
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
    /// turns the canonical vault into signable bytes
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

    /// computes and updated hmac
    pub fn seal_integrity(&mut self, hmac_key: &[u8; crypto::HMAC_KEY_LEN]) -> Result<()> {
        let bytes = self.signable_bytes()?;
        let tag = crypto::compute_hmac(hmac_key, &bytes);
        self.hmac = b64_encode(&tag);
        Ok(())
    }

    /// verifies if the seal has been tampered with by checking hmac
    pub fn verify_integrity(&self, hmac_key: &[u8; crypto::HMAC_KEY_LEN]) -> Result<()> {
        let stored = self.hmac.as_ref();
        let bytes = self.signable_bytes()?;
        let tag = b64_decode(stored)?;
        if !crypto::verify_hmac(hmac_key, &bytes, &tag) {
            return Err(anyhow!("SEAL TAMPERED: HMAC verification failed!"));
        }
        Ok(())
    }

    /// Generates a unique session cache scope string derived from the vault's path
    pub fn master_scope(&self) -> String {
        if let Some(path) = &self.file_path {
            let path_str = std::fs::canonicalize(path)
                .unwrap_or_else(|_| path.clone())
                .to_string_lossy()
                .to_string();

            let mut hasher = DefaultHasher::new();
            path_str.hash(&mut hasher);
            return format!("master_{:x}", hasher.finish());
        }
        "master_global".to_string()
    }

    /// Generates a unique session cache scope for a specific tag within this vault
    pub fn tag_scope(&self, group: Option<&str>, tag: &str) -> Result<String> {
        let group_name = self.resolve_group_name(group)?;
        Ok(format!(
            "{}_group_{}_tag_{}",
            self.master_scope(),
            group_name,
            tag
        ))
    }

    /// recursively search for .envseal file upwards
    fn find_local_seal(env_name: &str) -> Option<PathBuf> {
        let mut current_dir = env::current_dir().ok()?;
        loop {
            let candidate = current_dir.join(env_name);
            if candidate.exists() {
                return Some(candidate);
            }
            if !current_dir.pop() {
                break;
            }
        }
        None
    }

    /// find config/data directories acording to os
    pub fn resolve_path(
        force_local: bool,
        force_global: bool,
        pref: Option<&str>,
    ) -> Result<PathBuf> {
        if let Ok(override_path) = std::env::var("ENVSEAL_TEST_PATH") {
            return Ok(PathBuf::from(override_path));
        }

        let filename = match pref {
            Some(name) => format!(".{}.envseal", name),
            None => ".envseal".to_string(),
        };

        if force_local {
            return Ok(env::current_dir()?.join(filename));
        }

        if !force_global {
            if let Some(local_path) = Self::find_local_seal(&filename) {
                return Ok(local_path);
            }
        }

        let dirs = ProjectDirs::from("dev", "envseal", "envseal").ok_or_else(|| {
            anyhow!("Could not determine a config directory for this OS!! (Change your OS!!!)")
        })?;
        Ok(dirs.config_dir().join("seal-encrypted.json"))
    }

    /// checks if current vault is local or global
    pub fn is_local(&self) -> bool {
        self.file_path.as_ref().is_some_and(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            name == ".envseal" || name.ends_with(".envseal")
        })
    }

    /// creates and initiates vault
    pub fn init(password: &str, local: bool, global: bool, pref: Option<&str>) -> Result<()> {
        let path = Self::resolve_path(local, global, pref)?;
        if path.exists() {
            return Err(anyhow!(
                "Seal already exists at {:?}! Refusing to overwrite...",
                path
            ));
        }

        let salt = crypto::generate_salt();
        let (enc_key, hmac_key) = crypto::derive_keys(password, &salt)?;
        let (nonce, ciphertext) = crypto::encrypt(&enc_key, CANARY_PLAINTEXT)?;

        let mut entries = HashMap::new();

        // If local, automatically instantiate the root project group
        if local {
            entries.insert(
                LOCAL_GROUP_NAME.to_string(),
                Group {
                    link: PathBuf::new(),
                    base: HashMap::new(),
                    tags: HashMap::new(),
                },
            );
        }

        let mut vault = Vault {
            salt: b64_encode(&salt),
            canary: Entry {
                nonce: b64_encode(&nonce),
                ciphertext: b64_encode(&ciphertext),
            },
            link_index: HashMap::new(),
            entries,
            hmac: String::new(),
            file_path: Some(path),
        };

        vault.seal_integrity(&hmac_key)?;
        vault.save()
    }

    /// loads json to structures
    pub fn load(force_global: bool, pref: Option<&str>) -> Result<Self> {
        let path = Self::resolve_path(false, force_global, pref)?;
        let data = fs::read_to_string(&path)
            .map_err(|_| anyhow!("No seal found run 'envseal init' first!!"))?;

        let mut vault: Vault = serde_json::from_str(&data)?;

        vault.file_path = Some(path);

        Ok(vault)
    }

    /// atomically saves the changed structure into json
    pub fn save(&self) -> Result<()> {
        let path = self
            .file_path
            .as_ref()
            .ok_or_else(|| anyhow!("Vault path is not set!!"))?;

        let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));

        fs::create_dir_all(parent_dir).with_context(|| {
            format!(
                "Failed to create directory structure for '{}'",
                parent_dir.display()
            )
        })?;

        let mut temp_file = NamedTempFile::new_in(parent_dir).with_context(|| {
            format!(
                "Failed to create temporary file in '{}'",
                parent_dir.display()
            )
        })?;

        let json_data = serde_json::to_string_pretty(self)?;
        temp_file.write_all(json_data.as_bytes())?;
        temp_file.flush()?;

        temp_file.persist(path).map_err(|e| {
            anyhow!(
                "Failed to atomically write vault file to '{}': {}",
                path.display(),
                e.error
            )
        })?;

        Ok(())
    }

    /// resolves the group name from explicit value or link
    pub fn resolve_group_name(&self, group: Option<&str>) -> Result<String> {
        if self.is_local() {
            if group.is_some() {
                return Err(anyhow!(
                        "Local .envseal vaults do not support multiple groups! Please omit the --group flag."
                    ));
            }
            return Ok(LOCAL_GROUP_NAME.to_string());
        }

        if let Some(name) = group {
            Ok(name.to_string())
        } else {
            let cur_dir = env::current_dir()?;
            let name = self
                    .link_index
                    .get(&cur_dir)
                    .ok_or_else(|| anyhow!("No group linked to current directory!! Run `envseal link <group>` or use --group."))?;

            Ok(name.to_string())
        }
    }

    /// unlock protected tags
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
        let enc_key = crypto::derive_key(password, &salt)?;

        let nonce = b64_decode(&canary.nonce)?;
        let ciphertext = b64_decode(&canary.ciphertext)?;
        let plaintext = crypto::decrypt(&enc_key, &nonce, &ciphertext)
            .map_err(|_| anyhow!("Wrong Tag Password!!"))?;

        if plaintext != CANARY_PLAINTEXT {
            return Err(anyhow!("Wrong Tag Password!!"));
        }

        Ok(enc_key)
    }

    /// public unlock tag func
    pub fn unlock_tag(
        &self,
        group: Option<&str>,
        tag: &str,
        tag_password: &str,
    ) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>> {
        let group_name = self.resolve_group_name(group)?;

        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'!!"))?;

        let tag_entry = group_entry
            .tags
            .get(tag)
            .ok_or_else(|| anyhow!("No tag named '{tag}' in group '{group_name}'!!"))?;

        Self::unlock_tag_key(tag_entry, tag_password)
    }

    /// unlock master key and hmac key
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

        Ok(VaultKeys { enc_key, hmac_key })
    }

    /// link group to current directory
    pub fn link_group(&mut self, hmac_key: &[u8; crypto::HMAC_KEY_LEN], group: &str) -> Result<()> {
        if self.is_local() {
            return Err(anyhow!("Local .envseal vaults are automatically bound to their directory. Linking is only used for the global vault!!"));
        }

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

        group_entry.link = cur_dir.to_path_buf();
        self.link_index
            .insert(cur_dir.to_path_buf(), group.to_string());

        self.seal_integrity(hmac_key)?;
        Ok(())
    }

    /// create protected tag inside group
    pub fn create_protected_tag(
        &mut self,
        hmac_key: &[u8; crypto::HMAC_KEY_LEN],
        group: Option<&str>,
        tag: &str,
        tag_password: &str,
    ) -> Result<()> {
        if tag == BASE_TAG {
            return Err(anyhow!(
                    "Cannot create a tag named '{BASE_TAG}'. This is a reserved keyword for the default space!"
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

    /// check if a tag is protected or not
    pub fn is_tag_protected(&self, group: Option<&str>, tag: Option<&str>) -> Result<bool> {
        let tag = match tag {
            Some(val) => val,
            None => return Ok(false),
        };
        if tag == BASE_TAG {
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

    /// set entry into group/tag
    pub fn set_entry(
        &mut self,
        keys: &VaultKeys,
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
        value: &str,
        tag_key: Option<&[u8; crypto::KEY_LEN]>,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;

        let group_entry = self.entries.entry(group_name).or_insert_with(|| Group {
            link: PathBuf::new(),
            base: HashMap::new(),
            tags: HashMap::new(),
        });

        let active_tag = tag.unwrap_or(BASE_TAG);

        if active_tag == BASE_TAG {
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
                let tag_key = tag_key.ok_or_else(|| {
                    anyhow!("Tag '{active_tag}' is protected! Password required!!")
                })?;

                crypto::encrypt(tag_key, value)?
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

    /// fetches and decrypts an entry from group/tag
    pub fn get_entry(
        &self,
        key: &[u8; crypto::KEY_LEN],
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
        tag_key: Option<&[u8; crypto::KEY_LEN]>,
    ) -> Result<Zeroizing<String>> {
        let group_name = self.resolve_group_name(group)?;

        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'!!"))?;

        let active_tag = tag.unwrap_or(BASE_TAG);

        if active_tag == BASE_TAG {
            let entry = group_entry
                .base
                .get(name)
                .ok_or_else(|| anyhow!("No entry named '{name}' in group '{group_name}'!!"))?;

            let nonce = b64_decode(&entry.nonce)?;
            let ciphertext = b64_decode(&entry.ciphertext)?;
            let plaintext = crypto::decrypt(key, &nonce, &ciphertext)?;

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
            Zeroizing::new(
                *tag_key.ok_or_else(|| anyhow!("Password required for tag '{active_tag}'!"))?,
            )
        } else {
            Zeroizing::new(*key)
        };

        let nonce = b64_decode(&entry.nonce)?;
        let ciphertext = b64_decode(&entry.ciphertext)?;

        let plaintext = crypto::decrypt(&enc_key, &nonce, &ciphertext)?;

        Ok(Zeroizing::new(plaintext))
    }

    /// removes an entry from group/tag
    pub fn remove_entry(
        &mut self,
        hmac_key: &[u8; crypto::HMAC_KEY_LEN],
        group: Option<&str>,
        tag: Option<&str>,
        name: Option<&str>,
        tag_key: Option<&[u8; crypto::KEY_LEN]>,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;

        let active_tag = tag.unwrap_or(BASE_TAG);
        let name_str = name.unwrap_or("");

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
        if active_tag == BASE_TAG {
            // Reject attempting to remove the whole "base" tag
            if name_str.is_empty() {
                return Err(anyhow!(
                        "Cannot remove the reserved '{BASE_TAG}' tag entirely. You can only remove individual entries or the entire group!!"
                    ));
            }
        } else {
            let tag_ref = group_entry
                .tags
                .get(active_tag)
                .ok_or_else(|| anyhow!("No tag named '{active_tag}' in group '{group_name}'!!"))?;

            if tag_ref.salt.is_some() {
                let _ = tag_key.ok_or_else(|| {
                    anyhow!("Tag '{active_tag}' is protected! Password required to modify it.")
                })?;
            }
        }

        // Remove a whole tag from group (excluding 'base')
        if name_str.is_empty() && active_tag != BASE_TAG {
            group_entry.tags.remove(active_tag);
            self.seal_integrity(hmac_key)?;
            return Ok(());
        }

        // Remove an entry inside a tag
        if !name_str.is_empty() && active_tag != BASE_TAG {
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
        if active_tag == BASE_TAG && !name_str.is_empty() {
            group_entry
                .base
                .remove(name_str)
                .ok_or_else(|| anyhow!("No entry named '{name_str}' in group '{group_name}'!!"))?;

            self.seal_integrity(hmac_key)?;
        }

        Ok(())
    }

    /// list all key names(env var names) in a group/tag
    pub fn list_all_keys(&self, group: Option<&str>, tag: Option<&str>) -> Result<Vec<String>> {
        let group_name = self.resolve_group_name(group)?;

        // Geting the group entry
        let group_entry = self
            .entries
            .get(&group_name.to_string())
            .ok_or_else(|| anyhow!("No group named '{group_name}'!!"))?;

        // getting tag (base as default)
        let active_tag = tag.unwrap_or("base");

        // finding entries inside base and tag
        let keys: Vec<String> = if active_tag == BASE_TAG {
            group_entry.base.keys().cloned().collect()
        } else {
            group_entry
                .tags
                .get(active_tag)
                .ok_or_else(|| anyhow!("No tag named '{active_tag}' in group '{group_name}'!!"))?
                .entries
                .keys()
                .cloned()
                .collect()
        };

        Ok(keys)
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

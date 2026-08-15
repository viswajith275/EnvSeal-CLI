use super::crypto;
use super::token::{TokenKeyMaterial, TokenPayload};
use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const BASE_TAG: &str = "base";
const LOCAL_GROUP_NAME: &str = "project";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
    pub master_kek: Zeroizing<[u8; crypto::KEY_LEN]>, // used for rotating keys
    pub master_dek: Zeroizing<[u8; crypto::KEY_LEN]>, // used as master key
    #[zeroize(skip)]
    pub signing_key: SigningKey,  // for signing the file
}

impl fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultKeys")
            .field("master_kek", &"[REDACTED]")
            .field("master_dek", &"[REDACTED]")
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Tag {
    pub salt: Option<Vec<u8>>,
    pub wrapped_tag_dek: Option<Entry>,
    pub entries: BTreeMap<String, Entry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Group {
    pub link: PathBuf,
    pub base: BTreeMap<String, Entry>,
    pub tags: BTreeMap<String, Tag>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Vault {
    pub salt: Vec<u8>,
    pub public_key: Vec<u8>,
    pub wrapped_master_dek: Entry,
    pub link_index: BTreeMap<PathBuf, String>,
    pub entries: BTreeMap<String, Group>,

    #[serde(default)]
    pub signature: Vec<u8>,

    #[serde(skip)]
    pub file_path: Option<PathBuf>,
}

#[derive(Serialize)]
struct SignableVault<'a> {
    pub salt: &'a [u8],
    pub public_key: &'a [u8],
    pub wrapped_master_dek: &'a Entry,
    pub link_index: &'a BTreeMap<PathBuf, String>,
    pub entries: &'a BTreeMap<String, Group>,
    pub signature: &'a [u8],
}

impl Vault {
    /// turns the vault into signable bytes
    fn signable_bytes(&self) -> Result<Vec<u8>> {
        let sign = SignableVault {
            salt: &self.salt,
            public_key: &self.public_key,
            wrapped_master_dek: &self.wrapped_master_dek,
            link_index: &self.link_index,
            entries: &self.entries,
            signature: &[],
        };
        Ok(rmp_serde::to_vec(&sign)?)
    }

    /// Computes and updates the Ed25519 signature
    pub fn seal_integrity(&mut self, signing_key: &SigningKey) -> Result<()> {
        let bytes = self.signable_bytes()?;
        self.signature = signing_key.sign(&bytes).to_bytes().to_vec();
        Ok(())
    }

    /// Verifies the integrity of the files with Ed25519
    pub fn verify_integrity(&self) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(self.public_key.as_slice().try_into()?)
            .map_err(|_| anyhow!("Public key is corrupted!!"))?;

        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow!("Corrupted signature format in vault!!"))?;

        verifying_key
            .verify(&self.signable_bytes()?, &signature)
            .map_err(|_| anyhow!("SEAL TAMPERED: Ed25519 signature verification failed!!"))?;

        Ok(())
    }

    /// Universally decrypts any requested keys if the token possesses the derived key
    pub fn decrypt_from_token(
        &self,
        group: Option<&str>,
        tag: Option<&str>,
        token_payload: &TokenPayload,
    ) -> Result<BTreeMap<String, Zeroizing<String>>> {
        let mut decrypted_map = BTreeMap::new();
        let group_name = self.resolve_group_name(group)?;
        let active_tag = tag.unwrap_or(BASE_TAG);

        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow::anyhow!("Group not found!!"))?;

        let TokenKeyMaterial::GranularKeys(keys_map) = &token_payload.key_material;

        let mut target_entries: BTreeMap<&String, &Entry> = BTreeMap::new();

        // Load base entries
        for (var_name, entry) in &group_entry.base {
            target_entries.insert(var_name, entry);
        }

        // Tag entries overwrite base entries if duplicates exist
        if let Some(tag_entry) = group_entry.tags.get(active_tag) {
            for (var_name, entry) in &tag_entry.entries {
                target_entries.insert(var_name, entry);
            }
        }

        for (var_name, entry) in target_entries {
            if let Some(derived_key_bytes) = keys_map.get(var_name) {
                let mut entry_key = [0u8; crypto::KEY_LEN];
                entry_key.copy_from_slice(derived_key_bytes.as_slice());

                match crypto::decrypt(&entry_key, &entry.nonce, &entry.ciphertext) {
                    Ok(pt_bytes) => {
                        let plaintext = String::from_utf8(pt_bytes).context(
                            "Decrypted value conversion to UTF-8 failed, invalid string!!",
                        )?;
                        decrypted_map.insert(var_name.clone(), Zeroizing::new(plaintext));
                    }
                    Err(_) => {
                        eprintln!(
                            "Warning: Failed to decrypt '{}' , Token key may be outdated!!",
                            var_name
                        );
                    }
                }
            }
        }

        Ok(decrypted_map)
    }

    /// Generates a unique session cache scope string derived from the vault's path
    pub fn master_scope(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.public_key);
        let hash = hasher.finalize();
        format!("master_{}", hex::encode(hash))
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
            if current_dir.join(".git").exists()
                || current_dir.join(".hg").exists()
                || current_dir.join(".svn").exists()
            {
                break;
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
            return Err(anyhow!("Seal already exists at {:?}!", path));
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let salt = crypto::generate_salt();

        // Derive KEK and Signing Key
        let (master_kek, signing_key) = crypto::derive_master_keys(password, &salt)?;
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        let master_dek = crypto::generate_dek();
        let (nonce, ciphertext) = crypto::encrypt(&master_kek, &*master_dek)?;

        let mut entries = BTreeMap::new();

        if local {
            entries.insert(
                LOCAL_GROUP_NAME.to_string(),
                Group {
                    link: PathBuf::new(),
                    base: BTreeMap::new(),
                    tags: BTreeMap::new(),
                },
            );
        }

        let mut vault = Vault {
            salt: salt.to_vec(),
            public_key,
            wrapped_master_dek: Entry { nonce, ciphertext },
            link_index: BTreeMap::new(),
            entries,
            signature: vec![], // intialy empty done by seal_integrity
            file_path: Some(path),
        };

        vault.seal_integrity(&signing_key)?;
        vault.save()
    }

    /// loads json to structures
    pub fn load(force_global: bool, pref: Option<&str>) -> Result<Self> {
        let path = Self::resolve_path(false, force_global, pref)?;

        if !path.exists() {
            anyhow::bail!("No vault found, hint: Run 'envseal init' first!!");
        }

        let lock_path = path.with_extension("lock");

        let lock_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)?;

        lock_file
            .lock_shared()
            .with_context(|| format!("Failed to acquire read lock on '{}'", lock_path.display()))?;

        let mut file = File::open(&path)
            .with_context(|| format!("Failed to open vault at '{}'", path.display()))?;

        let mut data = Vec::new();

        file.read_to_end(&mut data)
            .with_context(|| format!("Failed to read vault data from '{}'", path.display()))?;

        lock_file.unlock()?;

        let mut vault: Vault = rmp_serde::from_slice(&data).with_context(|| {
            format!("Failed to deserialize vault data from '{}'", path.display())
        })?;
        vault.file_path = Some(path);
        Ok(vault)
    }

    /// Atomically saves the structure using MessagePack (rmp_serde).
    pub fn save(&self) -> Result<()> {
        let path = self.file_path.as_ref().context("File path not found!!")?;
        let lock_path = path.with_extension("lock");

        let lock_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)?;

        lock_file.lock_exclusive()?;

        let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp_file = NamedTempFile::new_in(parent_dir)?;

        let binary_data = rmp_serde::to_vec(self)?;
        temp_file.write_all(&binary_data)?;
        temp_file.flush()?;
        temp_file.persist(path)?;

        lock_file.unlock()?;
        let _ = fs::remove_file(lock_path);
        Ok(())
    }

    /// resolves the group name from explicit value or link
    pub fn resolve_group_name(&self, group: Option<&str>) -> Result<String> {
        if self.is_local() {
            if let Some(name) = group {
                if name != LOCAL_GROUP_NAME {
                    return Err(anyhow!(
                            "Local .envseal vaults do not support multiple groups!! Please omit the --group flag."
                        ));
                }
            }
            return Ok(LOCAL_GROUP_NAME.to_string());
        }

        if let Some(name) = group {
            return Ok(name.to_string());
        }

 i        let mut current = env::current_dir()?;
        loop {
            if let Some(group_name) = self.link_index.get(&current) {
                return Ok(group_name.clone());
            }
            if !current.pop() {
                break;
            }
        }

        Err(anyhow!(
                "No group linked to current directory or its parents!! Run `envseal link <group>` or use --group."
            ))
    }

    /// Rewraps the Master DEK under a new password without altering stored entries
    pub fn change_master_password(
        &mut self,
        current_keys: &VaultKeys,
        new_password: &str,
    ) -> Result<()> {
        let new_salt = crypto::generate_salt();
        let (new_master_kek, new_signing_key) =
            crypto::derive_master_keys(new_password, &new_salt)?;
        let new_public_key = new_signing_key.verifying_key().to_bytes().to_vec();

        let (nonce, ciphertext) = crypto::encrypt(&new_master_kek, &*current_keys.master_dek)?;

        let old_scope = self.master_scope();
        let _ = crate::utils::session::SessionManager::clear_session(&old_scope);

        self.salt = new_salt.to_vec();
        self.public_key = new_public_key;
        self.wrapped_master_dek = Entry { nonce, ciphertext };

        self.seal_integrity(&new_signing_key)?;
        self.save()?;

        let mut kek = [0u8; crypto::KEY_LEN];
        kek.copy_from_slice(&*new_master_kek);
        let mut seed = [0u8; crypto::KEY_LEN];
        seed.copy_from_slice(new_signing_key.to_bytes().as_slice());

        let _ = crate::utils::session::SessionManager::cache_keys(
            &self.master_scope(),
            crate::utils::session::CachedKeys::Master { kek, seed },
        );

        Ok(())
    }

    /// Rotate the DEK of a specific scope.
    /// Rotating BASE_TAG automatically sweeps and re-encrypts the entire vault (including unprotected tags).
    pub fn rotate_scope_dek(
        &mut self,
        keys: &VaultKeys,
        group: Option<&str>,
        tag: Option<&str>,
        old_tag_dek: Option<&[u8; crypto::KEY_LEN]>,
        tag_password: Option<&str>,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;
        let active_tag = tag.unwrap_or(BASE_TAG);

        if active_tag != BASE_TAG {
            let (is_unprotected, local_keys) = {
                let group_entry = self
                    .entries
                    .get(&group_name)
                    .ok_or_else(|| anyhow!("Group not found!!"))?;
                let tag_entry = group_entry
                    .tags
                    .get(active_tag)
                    .ok_or_else(|| anyhow!("Tag not found!!"))?;

                (
                    tag_entry.salt.is_none(),
                    tag_entry.entries.keys().cloned().collect::<Vec<String>>(),
                )
            };

            if is_unprotected {
                return Err(anyhow!("Cannot independently rotate an unprotected tag, Its security is mathematically bound to the Master DEK!!"));
            }

            let mut plaintexts = BTreeMap::new();
            for k in &local_keys {
                plaintexts.insert(
                    k.clone(),
                    self.get_entry(&keys.master_dek, group, tag, k, old_tag_dek)?,
                );
            }

            let group_entry = self
                .entries
                .get_mut(&group_name)
                .context("Group not found!!")?;
            let tag_entry = group_entry
                .tags
                .get_mut(active_tag)
                .context("Tag not found!!")?;

            let tp = tag_password.ok_or_else(|| anyhow!("Tag password required!!"))?;
            let salt = tag_entry
                .salt
                .as_ref()
                .context("Tag salt not found, corrupted file!!")?;
            let tag_kek = crypto::derive_key(tp, salt)?;

            let new_tag_dek = crypto::generate_dek();
            let (nonce, ciphertext) = crypto::encrypt(&tag_kek, &*new_tag_dek)?;
            tag_entry.wrapped_tag_dek = Some(Entry { nonce, ciphertext });

            for (k, v) in plaintexts {
                let entry_key = crypto::derive_entry_key(&new_tag_dek, &k);
                let (n, c) = crypto::encrypt(&entry_key, v.as_bytes())?;
                tag_entry.entries.insert(
                    k,
                    Entry {
                        nonce: n,
                        ciphertext: c,
                    },
                );
            }
        } else {
            let new_master_dek = crypto::generate_dek();

            let mut extraction_plan = Vec::new();
            for (g_name, g_entry) in &self.entries {
                let base_keys: Vec<String> = g_entry.base.keys().cloned().collect();
                let mut unprotected_tags = Vec::new();

                for (t_name, t_entry) in &g_entry.tags {
                    if t_entry.salt.is_none() {
                        unprotected_tags.push((
                            t_name.clone(),
                            t_entry.entries.keys().cloned().collect::<Vec<String>>(),
                        ));
                    }
                }
                extraction_plan.push((g_name.clone(), base_keys, unprotected_tags));
            }

            let mut all_base_plaintexts = BTreeMap::new();
            let mut all_unprotected_tags = BTreeMap::new();

            for (g_name, base_keys, unprotected_tags) in extraction_plan {
                let mut base_pts = BTreeMap::new();
                for k in base_keys {
                    base_pts.insert(
                        k.clone(),
                        self.get_entry(&keys.master_dek, Some(g_name.as_str()), None, &k, None)?,
                    );
                }
                all_base_plaintexts.insert(g_name.clone(), base_pts);

                let mut group_tag_pts = BTreeMap::new();
                for (t_name, tag_keys) in unprotected_tags {
                    let mut tag_pts = BTreeMap::new();
                    for k in tag_keys {
                        tag_pts.insert(
                            k.clone(),
                            self.get_entry(
                                &keys.master_dek,
                                Some(g_name.as_str()),
                                Some(t_name.as_str()),
                                &k,
                                None,
                            )?,
                        );
                    }
                    group_tag_pts.insert(t_name, tag_pts);
                }
                all_unprotected_tags.insert(g_name, group_tag_pts);
            }

            let (nonce, ciphertext) = crypto::encrypt(&keys.master_kek, &*new_master_dek)?;
            self.wrapped_master_dek = Entry { nonce, ciphertext };

            for (g_name, g_entry) in self.entries.iter_mut() {
                // Sweep Base
                if let Some(pts) = all_base_plaintexts.remove(g_name) {
                    let scope_dek = crypto::derive_scope_dek(&new_master_dek, g_name, BASE_TAG);
                    for (k, v) in pts {
                        let entry_key = crypto::derive_entry_key(&scope_dek, &k);
                        let (n, c) = crypto::encrypt(&entry_key, v.as_bytes())?;
                        g_entry.base.insert(
                            k,
                            Entry {
                                nonce: n,
                                ciphertext: c,
                            },
                        );
                    }
                }

                // Sweep Unprotected Tags
                if let Some(mut tag_pts_map) = all_unprotected_tags.remove(g_name) {
                    for (t_name, t_entry) in g_entry.tags.iter_mut() {
                        if t_entry.salt.is_none() {
                            if let Some(pts) = tag_pts_map.remove(t_name) {
                                let scope_dek =
                                    crypto::derive_scope_dek(&new_master_dek, g_name, t_name);
                                for (k, v) in pts {
                                    let entry_key = crypto::derive_entry_key(&scope_dek, &k);
                                    let (n, c) = crypto::encrypt(&entry_key, v.as_bytes())?;
                                    t_entry.entries.insert(
                                        k,
                                        Entry {
                                            nonce: n,
                                            ciphertext: c,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        self.seal_integrity(&keys.signing_key)?;
        Ok(())
    }

    /// unlock protected tags
    fn unlock_tag_key(tag: &Tag, password: &str) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>> {
        let salt = tag
            .salt
            .as_ref()
            .ok_or_else(|| anyhow!("Tag is not protected!!"))?;
        let wrapped_dek = tag
            .wrapped_tag_dek
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupted tag: missing wrapped DEK!!"))?;

        let tag_kek = crypto::derive_key(password, salt)?;

        let nonce = &wrapped_dek.nonce;
        let ciphertext = &wrapped_dek.ciphertext;

        let tag_dek_bytes = crypto::decrypt(&tag_kek, nonce, ciphertext)
            .map_err(|_| anyhow!("Wrong tag password!!"))?;

        let mut tag_dek = [0u8; crypto::KEY_LEN];
        tag_dek.copy_from_slice(&tag_dek_bytes);

        Ok(Zeroizing::new(tag_dek))
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

    /// unlock master key and
    pub fn unlock(&self, password: &str) -> Result<VaultKeys> {
        let salt = &self.salt;
        let (master_kek, signing_key) = crypto::derive_master_keys(password, salt)?;

        self.verify_integrity()?;

        let nonce = &self.wrapped_master_dek.nonce;
        let ciphertext = &self.wrapped_master_dek.ciphertext;

        let master_dek_bytes = crypto::decrypt(&master_kek, nonce, ciphertext)
            .map_err(|_| anyhow!("Wrong master password!!!"))?;

        let mut master_dek = [0u8; crypto::KEY_LEN];
        master_dek.copy_from_slice(&master_dek_bytes);

        Ok(VaultKeys {
            master_kek,
            master_dek: Zeroizing::new(master_dek),
            signing_key,
        })
    }

    /// link group to current directory
    pub fn link_group(&mut self, signing_key: &SigningKey, group: &str) -> Result<()> {
        if self.is_local() {
            return Err(anyhow!("Local .envseal vaults are automatically bound to their directory. Linking is only used for the global vault!!"));
        }

        if let Some(existing_group) = self.entries.get(group) {
            self.link_index.remove(&existing_group.link);
        }

        let cur_dir = env::current_dir()?;
        let group_entry = self
            .entries
            .entry(group.to_string())
            .or_insert_with(|| Group {
                link: PathBuf::new(),
                base: BTreeMap::new(),
                tags: BTreeMap::new(),
            });

        group_entry.link = cur_dir.to_path_buf();
        self.link_index
            .insert(cur_dir.to_path_buf(), group.to_string());

        self.seal_integrity(signing_key)?;
        Ok(())
    }

    /// create protected tag inside group
    pub fn create_protected_tag(
        &mut self,
        signing_key: &SigningKey,
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
                base: BTreeMap::new(),
                tags: BTreeMap::new(),
            });

        if group_entry.tags.contains_key(tag) {
            return Err(anyhow!(
                "Tag '{tag}' already exists in group '{group_name}'!"
            ));
        }

        let salt = crypto::generate_salt();
        let tag_kek = crypto::derive_key(tag_password, &salt)?;

        let tag_dek = crypto::generate_dek();
        let (nonce, ciphertext) = crypto::encrypt(&tag_kek, &*tag_dek)?;

        group_entry.tags.insert(
            tag.to_string(),
            Tag {
                salt: Some(salt.to_vec()),
                wrapped_tag_dek: Some(Entry { nonce, ciphertext }),
                entries: BTreeMap::new(),
            },
        );

        self.seal_integrity(signing_key)?;
        Ok(())
    }

    /// Check if a tag is protected or not
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

    /// Set entry into group/tag
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
        let group_entry = self
            .entries
            .entry(group_name.clone())
            .or_insert_with(|| Group {
                link: PathBuf::new(),
                base: BTreeMap::new(),
                tags: BTreeMap::new(),
            });

        let active_tag = tag.unwrap_or(BASE_TAG);

        let active_scope_dek = if active_tag == BASE_TAG {
            // Unprotected Base Tag: Derive from Master DEK
            crypto::derive_scope_dek(&keys.master_dek, &group_name, active_tag)
        } else {
            let tag_entry = group_entry.tags.entry(active_tag.to_string()).or_default();
            if tag_entry.salt.is_some() {
                // Protected Tag: Uses its own wrapped Tag DEK
                let tp = tag_key.ok_or_else(|| {
                    anyhow!("Tag '{active_tag}' is protected! Password required!!")
                })?;
                *tp
            } else {
                // Unprotected Tag: Derive from Master DEK
                crypto::derive_scope_dek(&keys.master_dek, &group_name, active_tag)
            }
        };

        // Derives the specific variable key
        let specific_entry_key = crypto::derive_entry_key(&active_scope_dek, name);

        let (nonce, ciphertext) = crypto::encrypt(&specific_entry_key, value.as_bytes())?;

        let entry = Entry { nonce, ciphertext };

        if active_tag == BASE_TAG {
            group_entry.base.insert(name.to_string(), entry);
        } else {
            let tag_entry = group_entry.tags.entry(active_tag.to_string()).or_default();
            tag_entry.entries.insert(name.to_string(), entry);
        }

        self.seal_integrity(&keys.signing_key)?;
        Ok(())
    }

    /// Fetches and decrypts an entry from group/tag
    pub fn get_entry(
        &self,
        master_dek: &[u8; crypto::KEY_LEN],
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
        tag_dek: Option<&[u8; crypto::KEY_LEN]>,
    ) -> Result<Zeroizing<String>> {
        let group_name = self.resolve_group_name(group)?;
        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'!!"))?;

        let active_tag = tag.unwrap_or(BASE_TAG);

        // Check the Active Tag (Overrides base)
        if active_tag != BASE_TAG {
            if let Some(tag_entry) = group_entry.tags.get(active_tag) {
                if let Some(entry) = tag_entry.entries.get(name) {
                    let active_scope_dek = if tag_entry.salt.is_some() {
                        let td = tag_dek.ok_or_else(|| {
                            anyhow!("Password required for protected tag '{active_tag}'!!")
                        })?;
                        *td
                    } else {
                        crypto::derive_scope_dek(master_dek, &group_name, active_tag)
                    };

                    let entry_key = crypto::derive_entry_key(&active_scope_dek, name);
                    let nonce = &entry.nonce;
                    let ciphertext = &entry.ciphertext;

                    let pt_bytes = crypto::decrypt(&entry_key, nonce, ciphertext)?;
                    let plaintext = String::from_utf8(pt_bytes).map_err(|_| {
                        anyhow!("Failed to parse decrypted data as a valid UTF-8 string!!")
                    })?;

                    return Ok(Zeroizing::new(plaintext));
                }
            }
        } else {
            if let Some(entry) = group_entry.base.get(name) {
                let base_scope_dek = crypto::derive_scope_dek(master_dek, &group_name, BASE_TAG);
                let entry_key = crypto::derive_entry_key(&base_scope_dek, name);
                let nonce = &entry.nonce;
                let ciphertext = &entry.ciphertext;

                let pt_bytes = crypto::decrypt(&entry_key, nonce, ciphertext)?;
                let plaintext = String::from_utf8(pt_bytes).map_err(|_| {
                    anyhow!("Failed to parse decrypted data as a valid UTF-8 string!!")
                })?;

                return Ok(Zeroizing::new(plaintext));
            }
        }

        Err(anyhow!("No entry '{name}' found in tag '{active_tag}'!!"))
    }

    /// removes an entry from group/tag
    pub fn remove_entry(
        &mut self,
        signing_key: &SigningKey,
        group: Option<&str>,
        tag: Option<&str>,
        name: Option<&str>,
        tag_key: Option<&[u8; crypto::KEY_LEN]>,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;

        let active_tag = tag.unwrap_or(BASE_TAG);
        let name_str = name.unwrap_or("");

        if tag.is_none() && name_str.is_empty() {
            if let Some(removed_group) = self.entries.remove(&group_name) {
                self.link_index.remove(&removed_group.link);
                self.seal_integrity(signing_key)?;
                return Ok(());
            } else {
                return Err(anyhow!("No group named '{group_name}'!!"));
            }
        }

        let group_entry = self
            .entries
            .get_mut(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'!!"))?;

        if active_tag == BASE_TAG {
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

        if name_str.is_empty() && active_tag != BASE_TAG {
            group_entry.tags.remove(active_tag);
            self.seal_integrity(signing_key)?;
            return Ok(());
        }

        if !name_str.is_empty() && active_tag != BASE_TAG {
            let tag_entry = group_entry
                .tags
                .get_mut(active_tag)
                .context("Tag not found!!")?;
            tag_entry.entries.remove(name_str).ok_or_else(|| {
                anyhow!(
                    "No entry named '{name_str}' in tag '{active_tag}' in group '{group_name}'!!"
                )
            })?;
            self.seal_integrity(signing_key)?;
            return Ok(());
        }

        if active_tag == BASE_TAG && !name_str.is_empty() {
            group_entry
                .base
                .remove(name_str)
                .ok_or_else(|| anyhow!("No entry named '{name_str}' in group '{group_name}'!!"))?;
            self.seal_integrity(signing_key)?;
        }

        Ok(())
    }

    /// list all key names(env var names) in a group/tag
    pub fn list_all_keys(&self, group: Option<&str>, tag: Option<&str>) -> Result<Vec<String>> {
        let group_name = self.resolve_group_name(group)?;
        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'!!"))?;

        let active_tag = tag.unwrap_or(BASE_TAG);

        // Load base keys into a HashSet to prevent duplicates
        let mut keys: HashSet<String> = group_entry.base.keys().cloned().collect();

        // Merge tag keys
        if active_tag != BASE_TAG {
            let tag_entry = group_entry
                .tags
                .get(active_tag)
                .ok_or_else(|| anyhow!("No tag named '{active_tag}' in group '{group_name}'!!"))?;

            for k in tag_entry.entries.keys() {
                keys.insert(k.clone());
            }
        }

        let mut sorted_keys: Vec<String> = keys.into_iter().collect();
        sorted_keys.sort();
        Ok(sorted_keys)
    }
}

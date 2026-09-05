use super::token::{TokenKeyMaterial, TokenManager, TokenPayload};
use super::{crypto, envelope};
use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const BASE_TAG: &str = "base";
pub const LOCAL_GROUP_NAME: &str = "project";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
    pub master_kek: Zeroizing<[u8; crypto::KEY_LEN]>,
    pub master_dek: Zeroizing<[u8; crypto::KEY_LEN]>,
    #[zeroize(skip)]
    pub signing_key: SigningKey,
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

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Serialize for Entry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let val = format!(
            "{}:{}",
            hex::encode(&self.nonce),
            hex::encode(&self.ciphertext)
        );
        serializer.serialize_str(&val)
    }
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let (nonce_hex, cipher_hex) = s
            .split_once(':')
            .ok_or_else(|| serde::de::Error::custom("expected format 'nonce:ciphertext'"))?;
        Ok(Self {
            nonce: hex::decode(nonce_hex).map_err(serde::de::Error::custom)?,
            ciphertext: hex::decode(cipher_hex).map_err(serde::de::Error::custom)?,
        })
    }
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub struct Tag {
    pub entries: BTreeMap<String, Entry>,
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub struct Group {
    pub link: PathBuf,
    pub base: BTreeMap<String, Entry>,
    pub tags: BTreeMap<String, Tag>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub struct Vault {
    pub recipients: Vec<String>,
    pub envelope: String,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    #[serde(default, with = "hex_bytes")]
    pub signature: Vec<u8>,
    pub link_index: BTreeMap<PathBuf, String>,
    pub entries: BTreeMap<String, Group>,

    #[serde(skip)]
    pub file_path: Option<PathBuf>,
}

#[derive(Serialize)]
struct SignableVault<'a> {
    pub recipients: &'a [String],
    pub envelope: &'a str,
    pub public_key: &'a [u8],
    pub link_index: &'a BTreeMap<PathBuf, String>,
    pub entries: &'a BTreeMap<String, Group>,
    pub signature: &'a [u8],
}

impl Vault {
    fn signable_bytes(&self) -> Result<Vec<u8>> {
        let sign = SignableVault {
            recipients: &self.recipients,
            envelope: &self.envelope,
            public_key: &self.public_key,
            link_index: &self.link_index,
            entries: &self.entries,
            signature: &[],
        };
        Ok(serde_json::to_vec(&sign)?)
    }

    pub fn seal_integrity(&mut self, signing_key: &SigningKey) -> Result<()> {
        let bytes = self.signable_bytes()?;
        self.signature = signing_key.sign(&bytes).to_bytes().to_vec();
        Ok(())
    }

    pub fn verify_integrity(&self) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(self.public_key.as_slice().try_into()?)
            .map_err(|_| anyhow!("Corrupted public key in vault"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow!("Corrupted signature format in vault"))?;
        verifying_key
            .verify(&self.signable_bytes()?, &signature)
            .map_err(|_| anyhow!("SEAL TAMPERED: Ed25519 signature verification failed"))?;
        Ok(())
    }

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
            .ok_or_else(|| anyhow!("Group '{group_name}' not found"))?;

        let TokenKeyMaterial::GranularKeys(keys_map) = &token_payload.key_material;
        let mut target_entries: BTreeMap<&String, &Entry> = BTreeMap::new();

        for (var_name, entry) in &group_entry.base {
            target_entries.insert(var_name, entry);
        }
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
                        let plaintext = String::from_utf8(pt_bytes)
                            .context("Decrypted value is not valid UTF-8")?;
                        decrypted_map.insert(var_name.clone(), Zeroizing::new(plaintext));
                    }
                    Err(_) => {
                        anyhow::bail!(
                            "Decryption failed for '{var_name}'. Token is revoked or invalid."
                        );
                    }
                }
            }
        }
        Ok(decrypted_map)
    }

    pub fn master_scope(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.public_key);
        format!("master_{}", hex::encode(hasher.finalize()))
    }

    pub fn tag_scope(&self, group: Option<&str>, tag: &str) -> Result<String> {
        let group_name = self.resolve_group_name(group)?;
        Ok(format!(
            "{}_group_{}:{}_tag_{}:{}",
            self.master_scope(),
            group_name.len(),
            group_name,
            tag.len(),
            tag
        ))
    }

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

    pub fn resolve_path(
        force_local: bool,
        force_global: bool,
        pref: Option<&str>,
    ) -> Result<PathBuf> {
        if let Ok(override_path) = std::env::var("ENVSEAL_TEST_PATH") {
            return Ok(PathBuf::from(override_path));
        }
        let filename = match pref {
            Some(name) => format!(".{name}.envseal"),
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
        let dirs = ProjectDirs::from("dev", "envseal", "envseal")
            .ok_or_else(|| anyhow!("Could not determine OS config directory"))?;
        Ok(dirs.config_dir().join("seal-encrypted.toml"))
    }

    pub fn is_local(&self) -> bool {
        self.file_path.as_ref().is_some_and(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            name == ".envseal" || name.ends_with(".envseal")
        })
    }

    pub fn init(
        recipients: Vec<String>,
        local: bool,
        global: bool,
        pref: Option<&str>,
    ) -> Result<()> {
        let path = Self::resolve_path(local, global, pref)?;
        if path.exists() {
            return Err(anyhow!("Seal already exists at {:?}!", path));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let signing_seed = crypto::generate_dek();
        let signing_key = SigningKey::from_bytes(&signing_seed);

        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let master_dek = crypto::generate_dek();

        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&*master_dek);
        payload[32..].copy_from_slice(signing_key.to_bytes().as_slice());

        let envelope = envelope::wrap_envelope(&payload, &recipients)?;

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
            recipients,
            envelope,
            public_key,
            signature: vec![],
            link_index: BTreeMap::new(),
            entries,
            file_path: Some(path),
        };
        vault.seal_integrity(&signing_key)?;
        vault.save()
    }

    pub fn load(force_global: bool, pref: Option<&str>) -> Result<Self> {
        let path = Self::resolve_path(false, force_global, pref)?;
        if !path.exists() {
            anyhow::bail!("No vault found. Run 'envseal init' first.");
        }
        let lock_path = path.with_extension("lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)?;
        lock_file
            .lock_shared()
            .with_context(|| format!("Failed to acquire read lock on '{}'", lock_path.display()))?;

        let mut file = File::open(&path)
            .with_context(|| format!("Failed to open vault at '{}'", path.display()))?;
        let mut data = String::new();
        file.read_to_string(&mut data)
            .with_context(|| format!("Failed to read vault data from '{}'", path.display()))?;
        lock_file.unlock()?;

        let mut vault: Vault = toml::from_str(&data)
            .with_context(|| format!("Failed to parse vault at '{}'", path.display()))?;
        vault.file_path = Some(path);
        Ok(vault)
    }

    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            anyhow::bail!("Vault file does not exist: {}", path.display());
        }
        let mut file = File::open(path)?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        let mut vault: Vault = toml::from_str(&data)?;
        vault.file_path = Some(path.clone());
        Ok(vault)
    }

    pub fn save(&self) -> Result<()> {
        let path = self.file_path.as_ref().context("Vault path not defined")?;
        let lock_path = path.with_extension("lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)?;
        lock_file.lock_exclusive()?;

        let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp_file = NamedTempFile::new_in(parent_dir)?;
        let toml_data = toml::to_string_pretty(self)?;
        temp_file.write_all(toml_data.as_bytes())?;
        temp_file.flush()?;
        temp_file.persist(path)?;
        lock_file.unlock()?;
        Ok(())
    }

    pub fn resolve_group_name(&self, group: Option<&str>) -> Result<String> {
        if self.is_local() {
            if let Some(name) = group {
                if name != LOCAL_GROUP_NAME {
                    return Err(anyhow!(
                        "Local vaults do not support multiple groups. Omit --group."
                    ));
                }
            }
            return Ok(LOCAL_GROUP_NAME.to_string());
        }
        if let Some(name) = group {
            return Ok(name.to_string());
        }
        let mut current = env::current_dir()?;
        loop {
            if let Some(group_name) = self.link_index.get(&current) {
                return Ok(group_name.clone());
            }
            if !current.pop() {
                break;
            }
        }
        Err(anyhow!(
            "No group linked to current directory. Run 'envseal link <group>' or pass --group."
        ))
    }

    pub fn unlock(&self, allow_env: bool) -> Result<VaultKeys> {
        self.verify_integrity()?;
        let payload = envelope::unwrap_envelope(&self.envelope, None, allow_env)?;

        let mut master_dek = [0u8; crypto::KEY_LEN];
        master_dek.copy_from_slice(&payload[..32]);
        let seed: &[u8; 32] = (&payload[32..64]).try_into().unwrap();
        let signing_key = SigningKey::from_bytes(seed);

        if self.public_key.as_slice() != signing_key.verifying_key().as_bytes() {
            anyhow::bail!("Vault public key does not match unlocked signing key");
        }

        Ok(VaultKeys {
            master_kek: Zeroizing::new([0u8; crypto::KEY_LEN]),
            master_dek: Zeroizing::new(master_dek),
            signing_key,
        })
    }

    pub fn link_group(&mut self, signing_key: &SigningKey, group: &str) -> Result<()> {
        if self.is_local() {
            return Err(anyhow!("Local vaults cannot configure linking"));
        }
        if let Some(existing_group) = self.entries.get(group) {
            self.link_index.remove(&existing_group.link);
        }
        let cur_dir = env::current_dir()?;
        let group_entry = self.entries.entry(group.to_string()).or_default();
        group_entry.link = cur_dir.clone();
        self.link_index.insert(cur_dir, group.to_string());
        self.seal_integrity(signing_key)?;
        Ok(())
    }

    pub fn set_entry(
        &mut self,
        keys: &VaultKeys,
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
        value: &str,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;
        let group_entry = self.entries.entry(group_name.clone()).or_default();

        let active_tag = tag.unwrap_or(BASE_TAG);
        let scope_dek = crypto::derive_scope_dek(&keys.master_dek, &group_name, active_tag);

        let entry_key = crypto::derive_entry_key(&scope_dek, name);
        let (nonce, ciphertext) = crypto::encrypt(&entry_key, value.as_bytes())?;

        let entry = Entry {
            nonce: nonce.to_vec(),
            ciphertext,
        };

        if active_tag == BASE_TAG {
            group_entry.base.insert(name.to_string(), entry);
        } else {
            let tag_entry = group_entry.tags.entry(active_tag.to_string()).or_default();
            tag_entry.entries.insert(name.to_string(), entry);
        }

        self.seal_integrity(&keys.signing_key)?;
        Ok(())
    }

    pub fn get_entry(
        &self,
        master_dek: &[u8; crypto::KEY_LEN],
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
    ) -> Result<Zeroizing<String>> {
        let group_name = self.resolve_group_name(group)?;
        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'"))?;
        let active_tag = tag.unwrap_or(BASE_TAG);

        if active_tag != BASE_TAG {
            if let Some(tag_entry) = group_entry.tags.get(active_tag) {
                if let Some(entry) = tag_entry.entries.get(name) {
                    let scope_dek = crypto::derive_scope_dek(master_dek, &group_name, active_tag);
                    let entry_key = crypto::derive_entry_key(&scope_dek, name);
                    let pt_bytes = crypto::decrypt(&entry_key, &entry.nonce, &entry.ciphertext)?;
                    let pt = String::from_utf8(pt_bytes).map_err(|_| anyhow!("Invalid UTF-8"))?;
                    return Ok(Zeroizing::new(pt));
                }
            }
        }

        if let Some(entry) = group_entry.base.get(name) {
            let base_scope_dek = crypto::derive_scope_dek(master_dek, &group_name, BASE_TAG);
            let entry_key = crypto::derive_entry_key(&base_scope_dek, name);
            let pt_bytes = crypto::decrypt(&entry_key, &entry.nonce, &entry.ciphertext)?;
            let pt = String::from_utf8(pt_bytes).map_err(|_| anyhow!("Invalid UTF-8"))?;
            return Ok(Zeroizing::new(pt));
        }

        Err(anyhow!(
            "No entry '{name}' found in tag '{active_tag}' or base"
        ))
    }

    pub fn remove_entry(
        &mut self,
        signing_key: &SigningKey,
        group: Option<&str>,
        tag: Option<&str>,
        name: Option<&str>,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;
        let active_tag = tag.unwrap_or(BASE_TAG);
        let name_str = name.unwrap_or("");

        if tag.is_none() && name_str.is_empty() {
            let removed_group = self
                .entries
                .remove(&group_name)
                .ok_or_else(|| anyhow!("No group named '{group_name}'"))?;
            self.link_index.remove(&removed_group.link);
            self.seal_integrity(signing_key)?;
            return Ok(());
        }

        let group_entry = self
            .entries
            .get_mut(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'"))?;

        if active_tag == BASE_TAG {
            if name_str.is_empty() {
                return Err(anyhow!("Cannot remove default '{BASE_TAG}' tag"));
            }
            group_entry
                .base
                .remove(name_str)
                .ok_or_else(|| anyhow!("No entry '{name_str}'"))?;
        } else if name_str.is_empty() {
            group_entry.tags.remove(active_tag);
        } else {
            let tag_entry = group_entry
                .tags
                .get_mut(active_tag)
                .context("Tag not found")?;
            tag_entry
                .entries
                .remove(name_str)
                .ok_or_else(|| anyhow!("No entry '{name_str}'"))?;
        }

        self.seal_integrity(signing_key)?;
        Ok(())
    }

    /// Generates granular entry keys for a token.
    /// Base variables are always included and overridden by values in the specified tag.
    pub fn generate_token_keys(
        &self,
        master_dek: &[u8; crypto::KEY_LEN],
        group: Option<&str>,
        tag: Option<&str>,
        filter_keys: Option<&[String]>,
    ) -> Result<std::collections::HashMap<String, Zeroizing<Vec<u8>>>> {
        let group_name = self.resolve_group_name(group)?;
        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("Group '{group_name}' not found"))?;
        let mut token_keys = std::collections::HashMap::new();
        let base_scope_dek = crypto::derive_scope_dek(master_dek, &group_name, BASE_TAG);

        for var_name in group_entry.base.keys() {
            if filter_keys.map_or(true, |fk| fk.is_empty() || fk.contains(var_name)) {
                let entry_key = crypto::derive_entry_key(&base_scope_dek, var_name);
                token_keys.insert(var_name.clone(), Zeroizing::new(entry_key.to_vec()));
            }
        }

        if let Some(target_tag) = tag {
            if target_tag != BASE_TAG {
                if let Some(tag_entry) = group_entry.tags.get(target_tag) {
                    let active_scope_dek =
                        crypto::derive_scope_dek(master_dek, &group_name, target_tag);
                    for var_name in tag_entry.entries.keys() {
                        if filter_keys.map_or(true, |fk| fk.is_empty() || fk.contains(var_name)) {
                            let entry_key = crypto::derive_entry_key(&active_scope_dek, var_name);
                            token_keys.insert(var_name.clone(), Zeroizing::new(entry_key.to_vec()));
                        }
                    }
                }
            }
        }
        Ok(token_keys)
    }

    pub fn create_token(
        &self,
        signing_key: &SigningKey,
        master_dek: &[u8; crypto::KEY_LEN],
        group: Option<&str>,
        tag: Option<&str>,
        sub: &str,
        ttl_seconds: Option<u64>,
        description: Option<&str>,
        filter_keys: Option<&[String]>,
    ) -> Result<String> {
        let active_tag = tag.unwrap_or(BASE_TAG);
        let scope_str = self.tag_scope(group, active_tag)?;
        let keys = self.generate_token_keys(master_dek, group, tag, filter_keys)?;
        TokenManager::create(signing_key, &scope_str, keys, sub, ttl_seconds, description)
    }

    pub fn rotate_dek(&mut self, keys: &VaultKeys) -> Result<()> {
        let new_master_dek = crypto::generate_dek();
        let mut base_pts = BTreeMap::new();
        let mut tag_pts = BTreeMap::new();

        for (g_name, g_entry) in &self.entries {
            let mut g_base = BTreeMap::new();
            for k in g_entry.base.keys() {
                g_base.insert(
                    k.clone(),
                    self.get_entry(&keys.master_dek, Some(g_name), None, k)?,
                );
            }
            base_pts.insert(g_name.clone(), g_base);

            let mut g_tags = BTreeMap::new();
            for (t_name, t_entry) in &g_entry.tags {
                let mut t_map = BTreeMap::new();
                for k in t_entry.entries.keys() {
                    t_map.insert(
                        k.clone(),
                        self.get_entry(&keys.master_dek, Some(g_name), Some(t_name), k)?,
                    );
                }
                g_tags.insert(t_name.clone(), t_map);
            }
            tag_pts.insert(g_name.clone(), g_tags);
        }

        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&*new_master_dek);
        payload[32..].copy_from_slice(keys.signing_key.to_bytes().as_slice());
        self.envelope = envelope::wrap_envelope(&payload, &self.recipients)?;

        for (g_name, g_entry) in self.entries.iter_mut() {
            if let Some(b_map) = base_pts.remove(g_name) {
                let scope_dek = crypto::derive_scope_dek(&new_master_dek, g_name, BASE_TAG);
                for (k, v) in b_map {
                    let entry_key = crypto::derive_entry_key(&scope_dek, &k);
                    let (n, c) = crypto::encrypt(&entry_key, v.as_bytes())?;
                    g_entry.base.insert(
                        k,
                        Entry {
                            nonce: n.to_vec(),
                            ciphertext: c,
                        },
                    );
                }
            }
            if let Some(mut t_map) = tag_pts.remove(g_name) {
                for (t_name, t_entry) in g_entry.tags.iter_mut() {
                    if let Some(k_map) = t_map.remove(t_name) {
                        let scope_dek = crypto::derive_scope_dek(&new_master_dek, g_name, t_name);
                        for (k, v) in k_map {
                            let entry_key = crypto::derive_entry_key(&scope_dek, &k);
                            let (n, c) = crypto::encrypt(&entry_key, v.as_bytes())?;
                            t_entry.entries.insert(
                                k,
                                Entry {
                                    nonce: n.to_vec(),
                                    ciphertext: c,
                                },
                            );
                        }
                    }
                }
            }
        }
        self.seal_integrity(&keys.signing_key)?;
        Ok(())
    }

    pub fn list_all_keys(&self, group: Option<&str>, tag: Option<&str>) -> Result<Vec<String>> {
        let group_name = self.resolve_group_name(group)?;
        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'"))?;
        let active_tag = tag.unwrap_or(BASE_TAG);
        let mut keys: HashSet<String> = group_entry.base.keys().cloned().collect();

        if active_tag != BASE_TAG {
            if let Some(tag_entry) = group_entry.tags.get(active_tag) {
                for k in tag_entry.entries.keys() {
                    keys.insert(k.clone());
                }
            }
        }
        let mut sorted_keys: Vec<String> = keys.into_iter().collect();
        sorted_keys.sort();
        Ok(sorted_keys)
    }
}

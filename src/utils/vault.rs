use super::token::{TokenKeyMaterial, TokenManager, TokenPayload};
use super::{crypto, envelope};
use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const BASE_TAG: &str = "base";
pub const LOCAL_GROUP_NAME: &str = "project";
pub const MAX_SECRET_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB
pub const MAX_VAULT_SIZE: u64 = 64 * 1024 * 1024; // 64 MB
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

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
    pub file_env: Option<String>,
    pub file_name: Option<String>,
    pub file_mode: Option<u32>,
}

// Support string format for text secrets and table format for file secrets
impl Serialize for Entry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(env) = &self.file_env {
            use serde::ser::SerializeMap;
            let mut len = 3;
            if self.file_name.is_some() {
                len += 1;
            }
            if self.file_mode.is_some() {
                len += 1;
            }
            let mut map = serializer.serialize_map(Some(len))?;
            map.serialize_entry("nonce", &hex::encode(&self.nonce))?;
            map.serialize_entry("ciphertext", &hex::encode(&self.ciphertext))?;
            map.serialize_entry("file_env", env)?;
            if let Some(name) = &self.file_name {
                map.serialize_entry("file_name", name)?;
            }
            if let Some(mode) = self.file_mode {
                map.serialize_entry("file_mode", &mode)?;
            }
            map.end()
        } else {
            let val = format!(
                "{}:{}",
                hex::encode(&self.nonce),
                hex::encode(&self.ciphertext)
            );
            serializer.serialize_str(&val)
        }
    }
}

// Support both nonce:ciphertext and table format
impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct EntryVisitor;

        impl<'de> Visitor<'de> for EntryVisitor {
            type Value = Entry;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string 'nonce:ciphertext' or a table with nonce, ciphertext, and optional file_env")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let (nonce_hex, cipher_hex) = value
                    .split_once(':')
                    .ok_or_else(|| de::Error::custom("expected format 'nonce:ciphertext'"))?;
                Ok(Entry {
                    nonce: hex::decode(nonce_hex).map_err(de::Error::custom)?,
                    ciphertext: hex::decode(cipher_hex).map_err(de::Error::custom)?,
                    file_env: None,
                    file_name: None,
                    file_mode: None,
                })
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: de::MapAccess<'de>,
            {
                let mut nonce = None;
                let mut ciphertext = None;
                let mut file_env = None;
                let mut file_name = None;
                let mut file_mode = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "nonce" => {
                            let val: String = map.next_value()?;
                            nonce = Some(hex::decode(&val).map_err(de::Error::custom)?);
                        }
                        "ciphertext" => {
                            let val: String = map.next_value()?;
                            ciphertext = Some(hex::decode(&val).map_err(de::Error::custom)?);
                        }
                        "file_env" => {
                            file_env = map.next_value()?;
                        }
                        "file_name" => {
                            file_name = map.next_value()?;
                        }
                        "file_mode" => {
                            file_mode = map.next_value()?;
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(Entry {
                    nonce: nonce.ok_or_else(|| de::Error::missing_field("nonce"))?,
                    ciphertext: ciphertext.ok_or_else(|| de::Error::missing_field("ciphertext"))?,
                    file_env,
                    file_name,
                    file_mode,
                })
            }
        }

        deserializer.deserialize_any(EntryVisitor)
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

/// Represents the fully decrypted state of a secret
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DecryptedValue {
    Text(Zeroizing<String>),
    File {
        env_name: String,
        bytes: Zeroizing<Vec<u8>>,
        file_name: Option<String>,
        file_mode: Option<u32>,
    },
}

/// Metadata for listing secrets
pub struct SecretInfo {
    pub name: String,
    pub is_file: bool,
    pub env_name: Option<String>,
}

impl Entry {
    pub fn decrypt(&self, entry_key: &[u8; crypto::KEY_LEN]) -> Result<DecryptedValue> {
        let pt_bytes = Zeroizing::new(crypto::decrypt(entry_key, &self.nonce, &self.ciphertext)?);

        if let Some(env_name) = &self.file_env {
            let is_zstd = pt_bytes.len() >= 4 && pt_bytes[0..4] == ZSTD_MAGIC;
            let final_bytes = if is_zstd {
                Zeroizing::new(zstd::stream::decode_all(pt_bytes.as_slice())?)
            } else {
                pt_bytes
            };
            Ok(DecryptedValue::File {
                env_name: env_name.clone(),
                bytes: final_bytes,
                file_name: self.file_name.clone(),
                file_mode: self.file_mode.map(|m| (m & 0o700) | 0o600),
            })
        } else {
            let text = String::from_utf8(pt_bytes.to_vec())
                .context("Decrypted value is not valid UTF-8")?;
            Ok(DecryptedValue::Text(Zeroizing::new(text)))
        }
    }
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

    pub fn decrypt_all(
        &self,
        master_dek: &[u8; crypto::KEY_LEN],
        group: Option<&str>,
        tag: Option<&str>,
    ) -> Result<BTreeMap<String, DecryptedValue>> {
        let group_name = self.resolve_group_name(group)?;
        let active_tag = tag.unwrap_or(BASE_TAG);
        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("Group '{group_name}' not found"))?;

        let base_scope_dek = crypto::derive_scope_dek(master_dek, &group_name, BASE_TAG);
        let tag_scope_dek = if active_tag != BASE_TAG {
            Some(crypto::derive_scope_dek(
                master_dek,
                &group_name,
                active_tag,
            ))
        } else {
            None
        };

        let mut target_entries = BTreeMap::new();
        for (k, v) in &group_entry.base {
            target_entries.insert(k.clone(), (v, BASE_TAG));
        }
        if active_tag != BASE_TAG {
            if let Some(tag_entry) = group_entry.tags.get(active_tag) {
                for (k, v) in &tag_entry.entries {
                    target_entries.insert(k.clone(), (v, active_tag));
                }
            }
        }

        let mut results = BTreeMap::new();

        for (name, (entry, entry_tag)) in target_entries {
            let scope_dek = if entry_tag == BASE_TAG {
                &base_scope_dek
            } else {
                tag_scope_dek.as_ref().unwrap()
            };
            let entry_key = crypto::derive_entry_key(scope_dek, &name);
            results.insert(name, entry.decrypt(&entry_key)?);
        }

        Ok(results)
    }

    pub fn decrypt_from_token(
        &self,
        group: Option<&str>,
        tag: Option<&str>,
        token_payload: &TokenPayload,
    ) -> Result<BTreeMap<String, DecryptedValue>> {
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
                match entry.decrypt(&entry_key) {
                    Ok(dec_val) => {
                        decrypted_map.insert(var_name.clone(), dec_val);
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
        hasher.update(self.envelope.as_bytes());
        format!("master_{}", hex::encode(hasher.finalize()))
    }

    /// v6 legacy socpes
    pub fn legacy_master_scope(&self) -> String {
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

    pub fn lock_path(path: &Path) -> PathBuf {
        PathBuf::from(format!("{}.lock", path.display()))
    }

    pub fn resolve_path(
        force_local: bool,
        force_global: bool,
        pref: Option<&str>,
    ) -> Result<PathBuf> {
        #[cfg(debug_assertions)]
        {
            if let Ok(override_path) = std::env::var("ENVSEAL_TEST_PATH") {
                return Ok(PathBuf::from(override_path));
            }
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
        let lock_path = Self::lock_path(&path);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)?;
        lock_file
            .lock_shared()
            .with_context(|| format!("Failed to acquire read lock on '{}'", lock_path.display()))?;

        let file = File::open(&path)
            .with_context(|| format!("Failed to open vault at '{}'", path.display()))?;
        let mut data = String::new();
        file.take(MAX_VAULT_SIZE + 1)
            .read_to_string(&mut data)
            .with_context(|| format!("Failed to read vault data from '{}'", path.display()))?;
        if data.len() as u64 > MAX_VAULT_SIZE {
            anyhow::bail!(
                "Vault at '{}' exceeds the maximum supported size of {} MB",
                path.display(),
                MAX_VAULT_SIZE / (1024 * 1024)
            );
        }
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
        let file = File::open(path)?;
        let mut data = String::new();
        file.take(MAX_VAULT_SIZE + 1).read_to_string(&mut data)?;
        if data.len() as u64 > MAX_VAULT_SIZE {
            anyhow::bail!(
                "Vault at '{}' exceeds the maximum supported size of {} MB",
                path.display(),
                MAX_VAULT_SIZE / (1024 * 1024)
            );
        }
        let mut vault: Vault = toml::from_str(&data)?;
        vault.file_path = Some(path.clone());
        Ok(vault)
    }

    pub fn save(&self) -> Result<()> {
        let path = self.file_path.as_ref().context("Vault path not defined")?;
        let lock_path = Self::lock_path(path);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)?;
        lock_file.lock_exclusive()?;

        // Drop legacy .lock file
        let legacy_lock = path.with_extension("lock");
        if legacy_lock != lock_path {
            let _ = fs::remove_file(&legacy_lock);
        }

        let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp_file = NamedTempFile::new_in(parent_dir)?;
        let toml_data = toml::to_string_pretty(self)?;
        temp_file.write_all(toml_data.as_bytes())?;
        temp_file.flush()?;
        temp_file.as_file().sync_all()?;
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

    // Only used when merging file secrets
    pub fn set_file_entry_raw(
        &mut self,
        keys: &VaultKeys,
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
        env_name: &str,
        data: &[u8],
        file_name: Option<String>,
        file_mode: Option<u32>,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;
        let active_tag = tag.unwrap_or(BASE_TAG);
        let group_entry = self.entries.entry(group_name.clone()).or_default();

        let compressed = Zeroizing::new(zstd::stream::encode_all(data, 3)?);
        let stored_bytes = if compressed.len() < data.len() {
            compressed
        } else {
            Zeroizing::new(data.to_vec())
        };

        let scope_dek = crypto::derive_scope_dek(&keys.master_dek, &group_name, active_tag);
        let entry_key = crypto::derive_entry_key(&scope_dek, name);
        let (nonce, ciphertext) = crypto::encrypt(&entry_key, stored_bytes.as_slice())?;

        let entry = Entry {
            nonce: nonce.to_vec(),
            ciphertext,
            file_env: Some(env_name.to_string()),
            file_name,
            file_mode,
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

    pub fn set_entry(
        &mut self,
        keys: &VaultKeys,
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
        value: &str,
    ) -> Result<()> {
        let group_name = self.resolve_group_name(group)?;
        let active_tag = tag.unwrap_or(BASE_TAG);
        let group_entry = self.entries.entry(group_name.clone()).or_default();

        // Check for Type Mismatch in the current scope
        let existing_in_scope = if active_tag == BASE_TAG {
            group_entry.base.get(name)
        } else {
            group_entry
                .tags
                .get(active_tag)
                .and_then(|t| t.entries.get(name))
                .or_else(|| group_entry.base.get(name))
        };

        if let Some(existing) = existing_in_scope {
            if existing.file_env.is_some() {
                anyhow::bail!(
                    "'{name}' is currently a file secret, Use 'envseal remove' to delete it before setting it as a text secret"
                );
            }
        }

        let mut existing_bindings: BTreeMap<&String, Option<&String>> = BTreeMap::new();
        for (k, v) in &group_entry.base {
            existing_bindings.insert(k, v.file_env.as_ref());
        }
        if active_tag != BASE_TAG {
            if let Some(t) = group_entry.tags.get(active_tag) {
                for (k, v) in &t.entries {
                    existing_bindings.insert(k, v.file_env.as_ref());
                }
            }
        }

        for (k, target_env) in existing_bindings {
            if let Some(t_env) = target_env {
                if t_env == name {
                    anyhow::bail!(
                        "Collision: '{name}' is already the target env variable for file secret '{k}'"
                    );
                }
            }
        }

        let scope_dek = crypto::derive_scope_dek(&keys.master_dek, &group_name, active_tag);
        let entry_key = crypto::derive_entry_key(&scope_dek, name);
        let (nonce, ciphertext) = crypto::encrypt(&entry_key, value.as_bytes())?;

        let entry = Entry {
            nonce: nonce.to_vec(),
            ciphertext,
            file_env: None,
            file_name: None,
            file_mode: None,
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

    pub fn set_file_entry(
        &mut self,
        keys: &VaultKeys,
        group: Option<&str>,
        tag: Option<&str>,
        name: &str,
        env_name: &str,
        path: &Path,
    ) -> Result<()> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            anyhow::bail!("Invalid file identifier: '{name}'");
        }

        if !super::is_valid_env_key(env_name) {
            anyhow::bail!("Invalid environment variable name: '{env_name}'");
        }

        let group_name = self.resolve_group_name(group)?;
        let group_entry = self.entries.entry(group_name.clone()).or_default();
        let active_tag = tag.unwrap_or(BASE_TAG);

        // Strict collision check for both key name and target env var
        let existing_in_scope = if active_tag == BASE_TAG {
            group_entry.base.get(name)
        } else {
            group_entry
                .tags
                .get(active_tag)
                .and_then(|t| t.entries.get(name))
                .or_else(|| group_entry.base.get(name))
        };

        if let Some(existing) = existing_in_scope {
            if existing.file_env.is_none() {
                anyhow::bail!(
                    "'{name}' is currently a text secret, Use 'envseal remove' to delete it before setting it as a file secret."
                );
            }
        }

        let mut existing_bindings: BTreeMap<&String, Option<&String>> = BTreeMap::new();
        for (k, v) in &group_entry.base {
            existing_bindings.insert(k, v.file_env.as_ref());
        }
        if active_tag != BASE_TAG {
            if let Some(t) = group_entry.tags.get(active_tag) {
                for (k, v) in &t.entries {
                    existing_bindings.insert(k, v.file_env.as_ref());
                }
            }
        }

        for (k, target_env) in existing_bindings {
            if k != name {
                if k == env_name {
                    anyhow::bail!(
                        "Collision: target env var '{env_name}' matches existing secret '{k}'"
                    );
                }
                if let Some(t_env) = target_env {
                    if t_env == env_name {
                        anyhow::bail!("Collision: target env var '{env_name}' is already used by file secret '{k}'");
                    }
                }
            }
        }

        let mut original = Zeroizing::new(Vec::new());
        File::open(path)?
            .take(MAX_SECRET_FILE_SIZE + 1)
            .read_to_end(&mut original)?;

        if original.len() as u64 > MAX_SECRET_FILE_SIZE {
            anyhow::bail!(
                "File exceeds the maximum supported size of {} MB",
                MAX_SECRET_FILE_SIZE / (1024 * 1024)
            );
        }

        // Compress only when the result is smaller than original
        let compressed = Zeroizing::new(zstd::stream::encode_all(original.as_slice(), 3)?);
        let stored_bytes = if compressed.len() < original.len() {
            compressed
        } else {
            original
        };

        let scope_dek = crypto::derive_scope_dek(&keys.master_dek, &group_name, active_tag);
        let entry_key = crypto::derive_entry_key(&scope_dek, name);
        let (nonce, ciphertext) = crypto::encrypt(&entry_key, stored_bytes.as_slice())?;

        let file_name = path.file_name().map(|n| n.to_string_lossy().to_string());

        #[cfg(unix)]
        let file_mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path).ok().map(|m| {
                if m.permissions().mode() & 0o111 != 0 {
                    0o700
                } else {
                    0o600
                }
            })
        };
        #[cfg(not(unix))]
        let file_mode = None;

        let entry = Entry {
            nonce: nonce.to_vec(),
            ciphertext,
            file_env: Some(env_name.to_string()),
            file_name,
            file_mode,
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

        let (entry, entry_tag) = if active_tag != BASE_TAG {
            if let Some(t_entry) = group_entry
                .tags
                .get(active_tag)
                .and_then(|t| t.entries.get(name))
            {
                (t_entry, active_tag)
            } else if let Some(b_entry) = group_entry.base.get(name) {
                (b_entry, BASE_TAG)
            } else {
                anyhow::bail!("No entry '{name}' found in tag '{active_tag}' or base");
            }
        } else {
            (
                group_entry.base.get(name).ok_or_else(|| {
                    anyhow!("No entry '{name}' found in tag '{active_tag}' or base")
                })?,
                BASE_TAG,
            )
        };

        if entry.file_env.is_some() {
            anyhow::bail!("'{name}' is a file secret");
        }

        let scope_dek = crypto::derive_scope_dek(master_dek, &group_name, entry_tag);
        let entry_key = crypto::derive_entry_key(&scope_dek, name);
        let pt_bytes = crypto::decrypt(&entry_key, &entry.nonce, &entry.ciphertext)?;
        let pt = String::from_utf8(pt_bytes).map_err(|_| anyhow!("Invalid UTF-8"))?;

        Ok(Zeroizing::new(pt))
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
            if self.is_local() {
                anyhow::bail!("Cannot remove root group in local vault, Specify a key to delete!!");
            }
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
            if filter_keys.is_none_or(|fk| fk.is_empty() || fk.contains(var_name)) {
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
                        if filter_keys.is_none_or(|fk| fk.is_empty() || fk.contains(var_name)) {
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
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&*new_master_dek);
        payload[32..].copy_from_slice(keys.signing_key.to_bytes().as_slice());
        self.envelope = envelope::wrap_envelope(&payload, &self.recipients)?;

        for (g_name, g_entry) in self.entries.iter_mut() {
            // Rotate base
            let base_scope_dek = crypto::derive_scope_dek(&new_master_dek, g_name, BASE_TAG);
            for (k, entry) in g_entry.base.iter_mut() {
                let old_scope_dek = crypto::derive_scope_dek(&keys.master_dek, g_name, BASE_TAG);
                let old_entry_key = crypto::derive_entry_key(&old_scope_dek, k);
                let pt_bytes = crypto::decrypt(&old_entry_key, &entry.nonce, &entry.ciphertext)?;

                let new_entry_key = crypto::derive_entry_key(&base_scope_dek, k);
                let (n, c) = crypto::encrypt(&new_entry_key, &pt_bytes)?;
                entry.nonce = n.to_vec();
                entry.ciphertext = c;
            }

            // Rotate tags
            for (t_name, t_entry) in g_entry.tags.iter_mut() {
                let tag_scope_dek = crypto::derive_scope_dek(&new_master_dek, g_name, t_name);
                for (k, entry) in t_entry.entries.iter_mut() {
                    let old_scope_dek = crypto::derive_scope_dek(&keys.master_dek, g_name, t_name);
                    let old_entry_key = crypto::derive_entry_key(&old_scope_dek, k);
                    let pt_bytes =
                        crypto::decrypt(&old_entry_key, &entry.nonce, &entry.ciphertext)?;

                    let new_entry_key = crypto::derive_entry_key(&tag_scope_dek, k);
                    let (n, c) = crypto::encrypt(&new_entry_key, &pt_bytes)?;
                    entry.nonce = n.to_vec();
                    entry.ciphertext = c;
                }
            }
        }
        self.seal_integrity(&keys.signing_key)?;
        Ok(())
    }

    /// Lists secrets with rich metadata (is_file, env_name)
    pub fn list_secrets(&self, group: Option<&str>, tag: Option<&str>) -> Result<Vec<SecretInfo>> {
        let group_name = self.resolve_group_name(group)?;
        let group_entry = self
            .entries
            .get(&group_name)
            .ok_or_else(|| anyhow!("No group named '{group_name}'"))?;
        let active_tag = tag.unwrap_or(BASE_TAG);

        let mut secrets = BTreeMap::new();

        // Base
        for (k, v) in &group_entry.base {
            secrets.insert(
                k.clone(),
                SecretInfo {
                    name: k.clone(),
                    is_file: v.file_env.is_some(),
                    env_name: v.file_env.clone(),
                },
            );
        }

        // Tag (overrides base)
        if active_tag != BASE_TAG {
            if let Some(tag_entry) = group_entry.tags.get(active_tag) {
                for (k, v) in &tag_entry.entries {
                    secrets.insert(
                        k.clone(),
                        SecretInfo {
                            name: k.clone(),
                            is_file: v.file_env.is_some(),
                            env_name: v.file_env.clone(),
                        },
                    );
                }
            }
        }

        Ok(secrets.into_values().collect())
    }
}

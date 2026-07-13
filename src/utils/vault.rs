use super::crypto;
use anyhow::{Ok, Result, anyhow};
use base64::Engine;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

const CANARY_PLAINTEXT: &str = "envfuse-Encrypted";

#[derive(Serialize, Deserialize)]
struct Entry {
    nonce: String,
    ciphertext: String,
}
 
#[derive(Serialize, Deserialize)]
pub struct Vault {
    salt: String,
    canary: Entry,
    entries: HashMap<String, Entry>,
}

impl Vault {
    // find config/data directories acording t os
    pub fn path() -> Result<PathBuf> {

        let dirs = ProjectDirs::from("dev", "envfuse", "envfuse").ok_or_else(|| anyhow!("could not determine a config directory for this OS"))?;
        
        Ok(dirs.config_dir().join("vault-encrypted.json"))
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
            entries: HashMap::new(),
        };
        vault.save()
    }

     pub fn load() -> Result<Self> {

        let path = Self::path()?;
        let data = fs::read_to_string(&path).map_err(|_| anyhow!("no vault found — run `envfuse init` first"))?;
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
        let plaintext = crypto::decrypt(&key, &nonce, &ciphertext).map_err(|_| anyhow!("wrong master password"))?;
 
        if plaintext != CANARY_PLAINTEXT {
            return Err(anyhow!("wrong master password"));
        }
        Ok(key)
    }

     pub fn add_entry(&mut self, key: &[u8; crypto::KEY_LEN], name: &str, value: &str) -> Result<()> {

        let (nonce, ciphertext) = crypto::encrypt(key, value)?;
        self.entries.insert(
            name.to_string(),
            Entry {
                nonce: b64_encode(&nonce),
                ciphertext: b64_encode(&ciphertext),
            },
        );
        Ok(())
    }
 
    pub fn get_entry(&self, key: &[u8; crypto::KEY_LEN], name: &str) -> Result<String> {

        let entry = self.entries.get(name).ok_or_else(|| anyhow!("no entry named '{name}'"))?;

        let nonce = b64_decode(&entry.nonce)?;
        let ciphertext = b64_decode(&entry.ciphertext)?;
        crypto::decrypt(key, &nonce, &ciphertext)
    } 

    pub fn remove_entry(&mut self, name: &str) -> Result<()> {

        let removed = self.entries.remove(name);

        if removed.is_some() {
            Ok(())
        } else {
            Err(anyhow!("no entry named '{name}'"))
        }    
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
 
fn b64_decode(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}
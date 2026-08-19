use crate::utils::{crypto, unlock, vault::Vault, vault::BASE_TAG};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub fn cmd_diff(file: &PathBuf, allow_env: bool) -> Result<()> {
    let vault = match Vault::load_from_file(file) {
        Ok(v) => v,
        Err(e) => {
            println!(
                "# [envseal] Unable to load vault file: {} ({e:#})",
                file.display()
            );
            return Ok(());
        }
    };

    if let Err(e) = vault.verify_integrity() {
        println!(
            "# [envseal] Integrity check FAILED for '{}': {e:#}",
            file.display()
        );
        println!("# [envseal] This vault may be corrupted or tampered with, Showing no content!!");
        return Ok(());
    }

    let master_keys = match unlock::sudo_unlock(&vault, None, allow_env) {
        Ok(k) => {
            if allow_env {
                eprintln!("# [envseal] WARNING: vault auto-unlocked via environment credential, plaintext secrets follow on stdout!!");
            }
            Some(k)
        }
        Err(e) => {
            eprintln!("# [envseal] Could not unlock master key: {e:#}");
            None
        }
    };

    if master_keys.is_none() {
        println!("# [envseal] Note: locked-entry fingerprints change on every reseal (fresh nonce), even when the underlying secret is unchanged!!");
    }

    let mut declined_tags: HashSet<String> = HashSet::new();

    for (group_name, group) in &vault.entries {
        println!("# Group: {}", group_name);
        println!("\n  [{}]", BASE_TAG);

        if let Some(ref keys) = master_keys {
            let base_scope_dek = crypto::derive_scope_dek(&keys.master_dek, group_name, BASE_TAG);
            for (key, entry) in &group.base {
                let entry_key = crypto::derive_entry_key(&base_scope_dek, key);
                match crypto::decrypt(&entry_key, &entry.nonce, &entry.ciphertext) {
                    Ok(pt) => {
                        let pt = Zeroizing::new(pt);
                        println!(
                            "  {} = {}",
                            key,
                            match std::str::from_utf8(&pt) {
                                Ok(s) => s.to_string(),
                                Err(_) => format!(
                                    "<binary: {} bytes, sha256:{}>",
                                    pt.len(),
                                    hex::encode(&Sha256::digest(pt)[..8])
                                ),
                            }
                        );
                    }
                    Err(_) => println!("  {} = <decryption-error>", key),
                }
            }
        } else {
            for (key, entry) in &group.base {
                let hash = Sha256::digest(&entry.ciphertext);
                println!(
                    "  {} = <locked: reseal-fingerprint:{}>",
                    key,
                    hex::encode(&hash[..8])
                );
            }
        }

        for (tag_name, tag) in &group.tags {
            println!("  [{}]", tag_name);

            let tag_dek = if let Some(ref keys) = master_keys {
                if tag.salt.is_some() {
                    if declined_tags.contains(tag_name) {
                        None
                    } else {
                        match unlock::sudo_unlock_tag(
                            &vault,
                            Some(group_name),
                            tag_name,
                            None,
                            allow_env,
                        ) {
                            Ok(dek) => Some(dek),
                            Err(e) => {
                                declined_tags.insert(tag_name.clone());
                                eprintln!(
                                    "# [envseal] Could not unlock tag '{tag_name}' in group '{group_name}': {e:#} (will not re-prompt for this tag name in this run)"
                                );
                                None
                            }
                        }
                    }
                } else {
                    Some(Zeroizing::new(crypto::derive_scope_dek(
                        &keys.master_dek,
                        group_name,
                        tag_name,
                    )))
                }
            } else {
                None
            };

            for (key, entry) in &tag.entries {
                if let Some(ref dek) = tag_dek {
                    let entry_key = crypto::derive_entry_key(dek, key);
                    match crypto::decrypt(&entry_key, &entry.nonce, &entry.ciphertext) {
                        Ok(pt) => {
                            let pt = Zeroizing::new(pt);
                            println!(
                                "  {} = {}",
                                key,
                                match std::str::from_utf8(&pt) {
                                    Ok(s) => s.to_string(),
                                    Err(_) => format!(
                                        "<binary: {} bytes, sha256:{}>",
                                        pt.len(),
                                        hex::encode(&Sha256::digest(pt)[..8])
                                    ),
                                }
                            );
                        }
                        Err(_) => println!("  {} = <decryption-error>", key),
                    }
                } else {
                    let hash = Sha256::digest(&entry.ciphertext);
                    println!(
                        "  {} = <locked: reseal-fingerprint:{}>",
                        key,
                        hex::encode(&hash[..8])
                    );
                }
            }
        }
    }

    Ok(())
}

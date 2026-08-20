use crate::utils::{vault::Vault, vault::BASE_TAG};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub fn cmd_diff(file: &PathBuf, _allow_env: bool) -> Result<()> {
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

    println!("# [envseal] Note: fingerprints change on every reseal (fresh nonce), even when the underlying secret is unchanged!!");

    for (group_name, group) in &vault.entries {
        println!("# Group: {}", group_name);
        println!("\n  [{}]", BASE_TAG);

        for (key, entry) in &group.base {
            let hash = Sha256::digest(&entry.ciphertext);
            println!(
                "  {} = <locked: reseal-fingerprint:{}>",
                key,
                hex::encode(&hash[..8])
            );
        }

        for (tag_name, tag) in &group.tags {
            println!("  [{}]", tag_name);

            for (key, entry) in &tag.entries {
                let hash = Sha256::digest(&entry.ciphertext);
                println!(
                    "  {} = <locked: reseal-fingerprint:{}>",
                    key,
                    hex::encode(&hash[..8])
                );
            }
        }
    }

    Ok(())
}

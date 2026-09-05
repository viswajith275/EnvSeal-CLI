use crate::cli::MergeStrategy;
use crate::utils::{crypto, unlock, vault::Group, vault::Vault, vault::BASE_TAG};
use anyhow::{anyhow, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use zeroize::Zeroizing;

fn parse_strategy_string(val: &str) -> Option<MergeStrategy> {
    match val.trim().to_lowercase().as_str() {
        "ours" => Some(MergeStrategy::Ours),
        "theirs" => Some(MergeStrategy::Theirs),
        "fail" => Some(MergeStrategy::Fail),
        _ => None,
    }
}

fn resolve_strategy(cli_strategy: &MergeStrategy) -> MergeStrategy {
    if cli_strategy != &MergeStrategy::Fail {
        return *cli_strategy;
    }

    if let Ok(output) = Command::new("git")
        .args(["config", "envseal.merge.strategy"])
        .output()
    {
        if output.status.success() {
            let config_val = String::from_utf8_lossy(&output.stdout);
            if let Some(strategy) = parse_strategy_string(&config_val) {
                eprintln!(
                    "[envseal] Using strategy '{}' from git config (envseal.merge.strategy)",
                    config_val.trim()
                );
                return strategy;
            }
        }
    }

    MergeStrategy::Fail
}

// decrypts all entries across base, ours, and theirs into memory simultaneously for 3-way diffing.
pub fn cmd_merge(
    base_path: &PathBuf,
    ours_path: &PathBuf,
    theirs_path: &PathBuf,
    cli_strategy: &MergeStrategy,
) -> Result<()> {
    eprintln!("[envseal] Starting 3-way cryptographic merge driver...");

    let strategy = &resolve_strategy(cli_strategy);

    let base_bytes = fs::read(base_path)
        .with_context(|| format!("Failed to read ancestor vault: {}", base_path.display()))?;
    let ours_bytes = fs::read(ours_path).with_context(|| {
        format!(
            "Failed to read current branch vault: {}",
            ours_path.display()
        )
    })?;
    let theirs_bytes = fs::read(theirs_path).with_context(|| {
        format!(
            "Failed to read incoming branch vault: {}",
            theirs_path.display()
        )
    })?;

    if ours_bytes == theirs_bytes {
        eprintln!("[envseal] Vaults on both branches are identical. No merge required.");
        return Ok(());
    }

    if theirs_bytes == base_bytes {
        eprintln!(
            "[envseal] Incoming branch made no changes to vault. Keeping current branch state."
        );
        return Ok(());
    }

    if ours_bytes == base_bytes {
        eprintln!(
            "[envseal] Current branch made no changes. Fast-forwarding to incoming branch vault..."
        );
        let theirs_vault = Vault::load_from_file(theirs_path)
            .context("Failed to load incoming vault for fast-forward")?;
        theirs_vault
            .verify_integrity()
            .context("Incoming vault integrity verification failed!")?;
        fs::copy(theirs_path, ours_path).with_context(|| {
            format!("Failed to copy incoming vault to '{}'", ours_path.display())
        })?;
        return Ok(());
    }

    let base_vault = Vault::load_from_file(base_path)
        .context("Failed to load ancestor (base) vault from Git")?;
    let mut ours_vault = Vault::load_from_file(ours_path)
        .context("Failed to load current branch (ours) vault from Git")?;
    let theirs_vault = Vault::load_from_file(theirs_path)
        .context("Failed to load incoming branch (theirs) vault from Git")?;

    base_vault
        .verify_integrity()
        .context("Ancestor 'base' vault signature check failed!")?;
    ours_vault
        .verify_integrity()
        .context("Current 'ours' vault signature check failed!")?;
    theirs_vault
        .verify_integrity()
        .context("Incoming 'theirs' vault signature check failed!")?;

    if ours_vault.entries == theirs_vault.entries {
        eprintln!("[envseal] Vault entries are identical. No reconciliation required.");
        return Ok(());
    }

    // Unlock master keys across all 3 commits using standard identities
    let ours_keys = unlock::sudo_unlock(&ours_vault, Some("current branch 'ours'"), false)?;
    let base_keys = unlock::sudo_unlock(&base_vault, Some("ancestor 'base'"), false)?;
    let theirs_keys = unlock::sudo_unlock(&theirs_vault, Some("incoming branch 'theirs'"), false)?;

    let all_groups: BTreeSet<String> = base_vault
        .entries
        .keys()
        .chain(ours_vault.entries.keys())
        .chain(theirs_vault.entries.keys())
        .cloned()
        .collect();

    let mut conflicts = Vec::new();

    for group_name in all_groups {
        let in_base = base_vault.entries.contains_key(&group_name);
        let in_ours = ours_vault.entries.contains_key(&group_name);
        let in_theirs = theirs_vault.entries.contains_key(&group_name);

        match (in_base, in_ours, in_theirs) {
            // Deleted on theirs
            (true, true, false) => {
                let ours_grp = ours_vault.entries.get(&group_name);
                let base_grp = base_vault.entries.get(&group_name);
                if ours_grp == base_grp {
                    ours_vault.entries.remove(&group_name);
                    eprintln!("[envseal] Group '{group_name}' deleted on incoming branch (no local changes) — removed.");
                    continue;
                }
                match strategy {
                    MergeStrategy::Theirs => {
                        ours_vault.entries.remove(&group_name);
                        continue;
                    }
                    MergeStrategy::Ours => continue,
                    _ => {
                        conflicts.push(format!(
                            "Group '{group_name}' modified locally but deleted on incoming branch."
                        ));
                        continue;
                    }
                }
            }
            // Deleted on ours
            (true, false, true) => {
                let theirs_grp = theirs_vault.entries.get(&group_name);
                let base_grp = base_vault.entries.get(&group_name);
                if theirs_grp == base_grp {
                    continue;
                }
                match strategy {
                    MergeStrategy::Ours => continue,
                    MergeStrategy::Theirs => {
                        ours_vault
                            .entries
                            .insert(group_name.clone(), theirs_grp.unwrap().clone());
                        continue;
                    }
                    _ => {
                        conflicts.push(format!(
                            "Group '{group_name}' deleted locally but modified on incoming branch."
                        ));
                        continue;
                    }
                }
            }
            (true, false, false) => continue,
            _ => {}
        }

        if !conflicts.is_empty() {
            break;
        }

        ours_vault
            .entries
            .entry(group_name.clone())
            .or_insert_with(|| Group {
                link: PathBuf::new(),
                base: BTreeMap::new(),
                tags: BTreeMap::new(),
            });

        let mut all_tags = BTreeSet::new();
        all_tags.insert(BASE_TAG.to_string());
        for v in [&base_vault, &ours_vault, &theirs_vault] {
            if let Some(g) = v.entries.get(&group_name) {
                all_tags.extend(g.tags.keys().cloned());
            }
        }

        for tag_name in all_tags {
            let tag_opt = (tag_name != BASE_TAG).then_some(tag_name.as_str());

            let base_entries =
                fetch_scope_map(&base_vault, &group_name, tag_opt, &base_keys.master_dek)?;
            let ours_entries =
                fetch_scope_map(&ours_vault, &group_name, tag_opt, &ours_keys.master_dek)?;
            let theirs_entries =
                fetch_scope_map(&theirs_vault, &group_name, tag_opt, &theirs_keys.master_dek)?;

            let all_keys: BTreeSet<String> = base_entries
                .keys()
                .chain(ours_entries.keys())
                .chain(theirs_entries.keys())
                .cloned()
                .collect();

            for key in all_keys {
                let v_base = base_entries.get(&key);
                let v_ours = ours_entries.get(&key);
                let v_theirs = theirs_entries.get(&key);

                let resolution: Option<Zeroizing<String>> = match (v_base, v_ours, v_theirs) {
                    (_, Some(o), Some(t)) if o == t => Some(o.clone()),
                    (b, o, Some(t)) if b == o => Some(t.clone()),
                    (b, o, None) if b == o => None,
                    (b, Some(o), t) if b == t => Some(o.clone()),
                    (b, None, t) if b == t => None,
                    _ => match strategy {
                        MergeStrategy::Ours => v_ours.cloned(),
                        MergeStrategy::Theirs => v_theirs.cloned(),
                        _ => {
                            conflicts.push(format!(
                                "Key '{key}' in group '{group_name}' [tag: '{tag_name}'] (conflicting modifications)"
                            ));
                            None
                        }
                    },
                };

                if conflicts.is_empty() {
                    match resolution {
                        Some(val) => {
                            ours_vault.set_entry(
                                &ours_keys,
                                Some(&group_name),
                                tag_opt,
                                &key,
                                val.as_str(),
                            )?;
                        }
                        None => {
                            // Only attempt removal if the key actually exists in ours
                            if v_ours.is_some() {
                                ours_vault.remove_entry(
                                    &ours_keys.signing_key,
                                    Some(&group_name),
                                    tag_opt,
                                    Some(&key),
                                )?;
                            }
                        }
                    }
                }
            }
        }
    }

    if !conflicts.is_empty() {
        eprintln!("[envseal] Merge conflict(s) encountered:");
        for c in &conflicts {
            eprintln!("  - {c}");
        }
        return Err(anyhow!("Merge halted due to conflicts. Resolve manually or re-run with --strategy=ours or --strategy=theirs."));
    }

    ours_vault.entries.retain(|_, g| {
        g.tags.retain(|_, t| !t.entries.is_empty());
        !g.base.is_empty() || !g.tags.is_empty()
    });

    ours_vault.seal_integrity(&ours_keys.signing_key)?;
    ours_vault.save()?;

    let _ = fs::remove_file(ours_path.with_extension("lock"));

    eprintln!(
        "[envseal] Successfully merged and resealed vault at '{}'",
        ours_path.display()
    );
    Ok(())
}

fn fetch_scope_map(
    vault: &Vault,
    group_name: &str,
    tag: Option<&str>,
    master_dek: &[u8; crypto::KEY_LEN],
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let mut map = BTreeMap::new();
    let Some(group) = vault.entries.get(group_name) else {
        return Ok(map);
    };
    let keys: Vec<String> = match tag {
        None => group.base.keys().cloned().collect(),
        Some(t) => group
            .tags
            .get(t)
            .map(|tag_struct| tag_struct.entries.keys().cloned().collect())
            .unwrap_or_default(),
    };
    for key in keys {
        let val = vault.get_entry(master_dek, Some(group_name), tag, &key)?;
        map.insert(key, val);
    }
    Ok(map)
}

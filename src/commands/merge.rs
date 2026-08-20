use crate::cli::MergeStrategy;
use crate::utils::{crypto, unlock, vault::Group, vault::Vault, vault::BASE_TAG};
use anyhow::{anyhow, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub fn cmd_merge(
    base_path: &PathBuf,
    ours_path: &PathBuf,
    theirs_path: &PathBuf,
    strategy: &MergeStrategy,
) -> Result<()> {
    eprintln!("[envseal] Starting 3-way cryptographic merge driver...");

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

    // Load vaults and verify Ed25519 signatures
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

    // unlock master keys for each branch
    let ours_keys = unlock::sudo_unlock(&ours_vault, Some("current branch 'ours'"), false)?;
    let base_dek = unlock_master_dek(&base_vault, &ours_keys, "ancestor 'base'")?;
    let theirs_dek = unlock_master_dek(&theirs_vault, &ours_keys, "incoming branch 'theirs'")?;

    // union of all groups across vaults
    let mut all_groups = BTreeSet::new();
    for g in base_vault.entries.keys() {
        all_groups.insert(g.clone());
    }
    for g in ours_vault.entries.keys() {
        all_groups.insert(g.clone());
    }
    for g in theirs_vault.entries.keys() {
        all_groups.insert(g.clone());
    }

    // prefetch the required passwords first
    let mut required: BTreeSet<(String, String)> = BTreeSet::new();

    for group_name in &all_groups {
        let mut tags_here = BTreeSet::new();
        tags_here.insert(BASE_TAG.to_string());
        for v in [&base_vault, &ours_vault, &theirs_vault] {
            if let Some(g) = v.entries.get(group_name) {
                for t in g.tags.keys() {
                    tags_here.insert(t.clone());
                }
            }
        }
        for tag_name in tags_here {
            if tag_name == BASE_TAG {
                continue;
            }
            let tag_opt = Some(tag_name.as_str());
            let needed = {
                let mut protected = false;
                for v in [&base_vault, &ours_vault, &theirs_vault] {
                    if is_tag_present(v, group_name, &tag_name) {
                        match v.is_tag_protected(Some(group_name), tag_opt) {
                            Ok(true) => protected = true,
                            Ok(false) => {}
                            Err(e) => {
                                return Err(anyhow!(
                                    "Failed to determine protection status for tag '{tag_name}' in group '{group_name}': {e:#} "
                                ));
                            }
                        }
                    }
                }
                protected
            };
            if needed {
                required.insert((group_name.clone(), tag_name));
            }
        }
    }

    eprintln!(
        "[envseal] Merge requires {} protected key(s):",
        required.len()
    );
    for (group, tag) in &required {
        eprintln!("  - group '{group}', tag '{tag}' ");
    }

    let mut prefetch_failures = Vec::new();
    for (group, tag) in &required {
        for (v, label) in [
            (&base_vault, "ancestor 'base'"),
            (&ours_vault, "current branch 'ours'"),
            (&theirs_vault, "incoming branch 'theirs'"),
        ] {
            if is_tag_present(v, group, tag)
                && v.is_tag_protected(Some(group), Some(tag.as_str()))
                    .unwrap_or(true)
            {
                if let Err(e) = unlock::sudo_unlock_tag(v, Some(group), tag, Some(label), false) {
                    prefetch_failures.push(format!(
                        "Cannot unlock protected tag '{tag}' in group '{group}' on {label}: {e:#}"
                    ));
                }
            }
        }
    }

    if !prefetch_failures.is_empty() {
        eprintln!("[envseal] Unable to unlock all required keys:");
        for f in &prefetch_failures {
            eprintln!("  - {f}");
        }
        return Err(anyhow!(
            "Merge halted: missing access to {} required key(s), Re-run with --strategy=ours or --strategy=theirs to skip them.",
            prefetch_failures.len()
        ));
    }

    let mut conflicts = Vec::new();

    for group_name in all_groups {
        // group presence permutations
        let in_base = base_vault.entries.contains_key(&group_name);
        let in_ours = ours_vault.entries.contains_key(&group_name);
        let in_theirs = theirs_vault.entries.contains_key(&group_name);

        match (in_base, in_ours, in_theirs) {
            // deleted on theirs, unchanged/present on ours honour deletion (unless ours changed it)
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
            // deleted on ours, still present on base -> mirror case, previously silently resurrected
            (true, false, true) => {
                let theirs_grp = theirs_vault.entries.get(&group_name);
                let base_grp = base_vault.entries.get(&group_name);
                if theirs_grp == base_grp {
                    // keep it deleted
                    continue;
                }
                match strategy {
                    MergeStrategy::Ours => continue, // keep it deleted
                    MergeStrategy::Theirs => {
                        ours_vault
                            .entries
                            .insert(group_name.clone(), theirs_grp.unwrap().clone());
                    }
                    _ => {
                        conflicts.push(format!(
                            "Group '{group_name}' deleted locally but modified on incoming branch."
                        ));
                        continue;
                    }
                }
            }
            // deleted on both branches independently
            (true, false, false) => continue,
            // new group, only on one or both branches
            _ => {}
        }

        if !conflicts.is_empty() {
            break;
        }

        // ensure group container exists in 'ours'
        ours_vault
            .entries
            .entry(group_name.clone())
            .or_insert_with(|| Group {
                link: PathBuf::new(),
                base: BTreeMap::new(),
                tags: BTreeMap::new(),
            });

        // collect all tags for this group
        let mut all_tags = BTreeSet::new();
        all_tags.insert(BASE_TAG.to_string());
        if let Some(g) = base_vault.entries.get(&group_name) {
            for t in g.tags.keys() {
                all_tags.insert(t.clone());
            }
        }
        if let Some(g) = ours_vault.entries.get(&group_name) {
            for t in g.tags.keys() {
                all_tags.insert(t.clone());
            }
        }
        if let Some(g) = theirs_vault.entries.get(&group_name) {
            for t in g.tags.keys() {
                all_tags.insert(t.clone());
            }
        }

        for tag_name in all_tags {
            let tag_opt = if tag_name == BASE_TAG {
                None
            } else {
                Some(tag_name.as_str())
            };

            let tag_in_base = is_tag_present(&base_vault, &group_name, &tag_name);
            let tag_in_ours = is_tag_present(&ours_vault, &group_name, &tag_name);
            let tag_in_theirs = is_tag_present(&theirs_vault, &group_name, &tag_name);

            let base_is_protected = if tag_in_base {
                base_vault.is_tag_protected(Some(&group_name), tag_opt)
                    .with_context(|| format!(
                        "Failed to determine protection status for tag '{tag_name}' in group '{group_name}' (ancestor 'base')"
                    ))?
            } else {
                false
            };

            let ours_is_protected = if tag_in_ours {
                ours_vault.is_tag_protected(Some(&group_name), tag_opt)
                    .with_context(|| format!(
                        "Failed to determine protection status for tag '{tag_name}' in group '{group_name}' (current branch 'ours')"
                    ))?
            } else {
                false
            };

            let theirs_is_protected = if tag_in_theirs {
                theirs_vault.is_tag_protected(Some(&group_name), tag_opt)
                    .with_context(|| format!(
                        "Failed to determine protection status for tag '{tag_name}' in group '{group_name}' (incoming branch 'theirs')"
                    ))?
            } else {
                false
            };

            // Raw tag comparison and fast-path only apply to PROTECTED tags
            if base_is_protected || ours_is_protected || theirs_is_protected {
                let base_tag_raw = base_vault
                    .entries
                    .get(&group_name)
                    .and_then(|g| g.tags.get(&tag_name));
                let ours_tag_raw = ours_vault
                    .entries
                    .get(&group_name)
                    .and_then(|g| g.tags.get(&tag_name));
                let theirs_tag_raw = theirs_vault
                    .entries
                    .get(&group_name)
                    .and_then(|g| g.tags.get(&tag_name));

                // raw structs identical on both branches: nothing to do
                if ours_tag_raw.is_some() && ours_tag_raw == theirs_tag_raw {
                    continue;
                }

                // rotected tag created ONLY in 'theirs': blind import sealed struct
                if base_tag_raw.is_none() && ours_tag_raw.is_none() && theirs_is_protected {
                    if let Some(tr) = theirs_tag_raw {
                        let group_entry = ours_vault.entries.get_mut(&group_name).unwrap();
                        group_entry.tags.insert(tag_name.clone(), tr.clone());
                        eprintln!("[envseal] Protected tag '{tag_name}' imported sealed (no password required).");
                        continue;
                    }
                }

                // 'ours' unchanged from 'base': fast-forward directly to 'theirs'
                if base_tag_raw.is_some() && ours_tag_raw == base_tag_raw {
                    let group_entry = ours_vault.entries.get_mut(&group_name).unwrap();
                    if let Some(t_tag) = theirs_tag_raw {
                        group_entry.tags.insert(tag_name.clone(), t_tag.clone());
                        eprintln!("[envseal] Protected tag '{tag_name}' fast-forwarded from incoming branch (no password required).");
                    } else {
                        group_entry.tags.remove(&tag_name);
                        eprintln!("[envseal] Protected tag '{tag_name}' removed (deleted on incoming branch).");
                    }
                    continue;
                }

                // 'theirs' unchanged from 'base': keep 'ours'
                if base_tag_raw.is_some() && theirs_tag_raw == base_tag_raw {
                    continue;
                }

                // Strategy overrides for protected tags
                if strategy == &MergeStrategy::Ours {
                    continue;
                }
                if strategy == &MergeStrategy::Theirs {
                    let group_entry = ours_vault.entries.get_mut(&group_name).unwrap();
                    if let Some(t_tag) = theirs_tag_raw {
                        group_entry.tags.insert(tag_name.clone(), t_tag.clone());
                    } else {
                        group_entry.tags.remove(&tag_name);
                    }
                    continue;
                }
            }

            let tag_in_base = is_tag_present(&base_vault, &group_name, &tag_name);
            let tag_in_ours = is_tag_present(&ours_vault, &group_name, &tag_name);
            let tag_in_theirs = is_tag_present(&theirs_vault, &group_name, &tag_name);

            // unlock protected tags on demand; unprotected tags use Master DEK
            let ours_tag_dek = if ours_is_protected && tag_in_ours {
                match unlock::sudo_unlock_tag(
                    &ours_vault,
                    Some(&group_name),
                    &tag_name,
                    Some("current branch 'ours'"),
                    false,
                ) {
                    Ok(dek) => Some(dek),
                    Err(e) => {
                        conflicts.push(format!(
                            "Cannot decrypt protected tag '{tag_name}' in group '{group_name}' on incoming branch: {e:#}. \
                             Resolve using --strategy=ours or --strategy=theirs."
                        ));
                        continue;
                    }
                }
            } else {
                None
            };

            let theirs_tag_dek = if theirs_is_protected && tag_in_theirs {
                match unlock::sudo_unlock_tag(
                    &theirs_vault,
                    Some(&group_name),
                    &tag_name,
                    Some("incoming branch 'theirs'"),
                    false,
                ) {
                    Ok(dek) => Some(dek),
                    Err(e) => {
                        conflicts.push(format!(
                            "Cannot decrypt protected tag '{tag_name}' in group '{group_name}' on incoming branch: {e:#}. \
                             Resolve using --strategy=ours or --strategy=theirs."
                        ));
                        continue;
                    }
                }
            } else {
                None
            };

            let base_tag_dek = if base_is_protected && tag_in_base {
                match unlock::sudo_unlock_tag(
                    &base_vault,
                    Some(&group_name),
                    &tag_name,
                    Some("ancestor 'base'"),
                    false,
                ) {
                    Ok(dek) => Some(dek),
                    Err(e) => {
                        conflicts.push(format!(
                            "Cannot decrypt protected tag '{tag_name}' in group '{group_name}' on incoming branch: {e:#}. \
                             Resolve using --strategy=ours or --strategy=theirs."
                        ));
                        continue;
                    }
                }
            } else {
                None
            };

            if !conflicts.is_empty() {
                break;
            }

            // decrypt scopes
            let base_entries = if tag_in_base {
                fetch_scope_map(
                    &base_vault,
                    &group_name,
                    tag_opt,
                    &base_dek,
                    base_tag_dek.as_deref(),
                )?
            } else {
                BTreeMap::new()
            };

            let ours_entries = if tag_in_ours {
                fetch_scope_map(
                    &ours_vault,
                    &group_name,
                    tag_opt,
                    &ours_keys.master_dek,
                    ours_tag_dek.as_deref(),
                )?
            } else {
                BTreeMap::new()
            };

            let theirs_entries = if tag_in_theirs {
                fetch_scope_map(
                    &theirs_vault,
                    &group_name,
                    tag_opt,
                    &theirs_dek,
                    theirs_tag_dek.as_deref(),
                )?
            } else {
                BTreeMap::new()
            };

            let mut all_keys = BTreeSet::new();
            for k in base_entries.keys() {
                all_keys.insert(k.clone());
            }
            for k in ours_entries.keys() {
                all_keys.insert(k.clone());
            }
            for k in theirs_entries.keys() {
                all_keys.insert(k.clone());
            }

            for key in all_keys {
                let v_base = base_entries.get(&key);
                let v_ours = ours_entries.get(&key);
                let v_theirs = theirs_entries.get(&key);

                let resolution: Option<Zeroizing<String>> = match (v_base, v_ours, v_theirs) {
                    // both branches identical
                    (_, Some(o), Some(t)) if o == t => Some(o.clone()),
                    // changed only in 'theirs':  fast-forward
                    (b, o, Some(t)) if b == o => Some(t.clone()),
                    // deleted only in 'theirs': delete
                    (b, o, None) if b == o => None,
                    // changed only in 'ours': keep ours
                    (b, Some(o), t) if b == t => Some(o.clone()),
                    // deleted only in 'ours':  keep deleted
                    (b, None, t) if b == t => None,
                    // conflicting states
                    _ => match strategy {
                        MergeStrategy::Ours => v_ours.cloned(),
                        MergeStrategy::Theirs => v_theirs.cloned(),
                        _ => {
                            // redact actual plaintext values from logs to prevent terminal/scrollback leaks
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
                                ours_tag_dek.as_deref(),
                            )?;
                        }
                        None => {
                            ours_vault
                                .remove_entry(
                                    &ours_keys.signing_key,
                                    Some(&group_name),
                                    tag_opt,
                                    Some(&key),
                                    ours_tag_dek.as_deref(),
                                )
                                .with_context(|| {
                                    format!(
                                        "Failed to remove entry '{key}' from group '{group_name}' "
                                    )
                                })?;
                        }
                    }
                }
            }
        }
    }

    if !conflicts.is_empty() {
        eprintln!("[envseal] Merge conflict(s) encountered:");
        for c in conflicts {
            eprintln!("  - {}", c);
        }
        return Err(anyhow!("Merge halted due to conflicts. Resolve manually or re-run with --strategy=ours or --strategy=theirs."));
    }

    // removing any stray/empty groups
    ours_vault
        .entries
        .retain(|_, g| !g.base.is_empty() || !g.tags.is_empty());

    // reseal and persist into %A (ansester path)
    ours_vault.seal_integrity(&ours_keys.signing_key)?;
    ours_vault.save()?;

    eprintln!(
        "[envseal] Successfully merged and resealed vault at '{}'",
        ours_path.display()
    );
    Ok(())
}

fn unlock_master_dek(
    vault: &Vault,
    ours_keys: &crate::utils::vault::VaultKeys,
    label: &str,
) -> Result<Zeroizing<[u8; crypto::KEY_LEN]>> {
    if let Ok(master_dek_bytes) = crypto::decrypt(
        &ours_keys.master_kek,
        &vault.wrapped_master_dek.nonce,
        &vault.wrapped_master_dek.ciphertext,
    ) {
        let master_dek_bytes = Zeroizing::new(master_dek_bytes);
        let mut dek = [0u8; crypto::KEY_LEN];
        dek.copy_from_slice(&master_dek_bytes);
        return Ok(Zeroizing::new(dek));
    }
    let unlocked = unlock::sudo_unlock(vault, Some(label), false)?;
    Ok(Zeroizing::new(*unlocked.master_dek))
}

fn fetch_scope_map(
    vault: &Vault,
    group_name: &str,
    tag: Option<&str>,
    master_dek: &[u8; crypto::KEY_LEN],
    tag_dek: Option<&[u8; crypto::KEY_LEN]>,
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
        let val = vault.get_entry(master_dek, Some(group_name), tag, &key, tag_dek)
            .with_context(|| format!(
                "Failed to decrypt entry '{key}' in group '{group_name}' , vault may be corrupted or tampered!!"
            ))?;
        map.insert(key, val);
    }

    Ok(map)
}

fn is_tag_present(vault: &Vault, group_name: &str, tag_name: &str) -> bool {
    vault.entries.get(group_name).is_some_and(|g| {
        if tag_name == BASE_TAG {
            !g.base.is_empty()
        } else {
            g.tags.contains_key(tag_name)
        }
    })
}

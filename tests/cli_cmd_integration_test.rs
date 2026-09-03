use assert_cmd::Command;
use envseal::utils::crypto;
use envseal::utils::token::TokenManager;
use envseal::utils::vault::{Entry, Group, Vault, BASE_TAG};
use predicates::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use zeroize::Zeroizing;

/// Helper to configure a clean envseal command isolated to a specific working directory
fn envseal_cmd(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("envseal").expect("Failed to locate envseal binary");
    cmd.current_dir(dir);
    cmd.env_remove("ENVSEAL_TEST_PATH");
    cmd.env_remove("ENVSEAL_PASSWORD");
    cmd.env_remove("ENVSEAL_TAG_PASSWORD");
    cmd.env_remove("ENVSEAL_TOKEN");
    cmd.env_remove("ENVSEAL_TOKEN_FILE");
    cmd
}

/// Helper to generate a cross-platform askpass executable for non-interactive Git driver auth
fn create_askpass_script(dir: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script_path = dir.join("askpass.sh");
        fs::write(
            &script_path,
            "#!/bin/sh\nprintf '%s' \"$ENVSEAL_PASSWORD\"\n",
        )
        .unwrap();
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
        script_path
    }
    #[cfg(windows)]
    {
        let script_path = dir.join("askpass.bat");
        fs::write(&script_path, "@echo off\r\necho %ENVSEAL_PASSWORD%\r\n").unwrap();
        script_path
    }
}

/// Thread-safe helper to initialize and persist a test vault directly at `path`
/// without mutating process-wide environment variables.
fn create_fixture_vault(path: &Path, password: &str, entries: &[(&str, &str)]) -> Vault {
    let salt = crypto::generate_salt();
    let (master_kek, signing_key) = crypto::derive_master_keys(password, &salt).unwrap();
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    let master_dek = crypto::generate_dek();
    let (nonce, ciphertext) = crypto::encrypt(&master_kek, &*master_dek).unwrap();

    let mut base_map = BTreeMap::new();
    let scope_dek = crypto::derive_scope_dek(&master_dek, "project", BASE_TAG);
    for (k, v) in entries {
        let entry_key = crypto::derive_entry_key(&scope_dek, k);
        let (n, c) = crypto::encrypt(&entry_key, v.as_bytes()).unwrap();
        base_map.insert(
            k.to_string(),
            Entry {
                nonce: n,
                ciphertext: c,
            },
        );
    }

    let mut group_entries = BTreeMap::new();
    group_entries.insert(
        "project".to_string(),
        Group {
            link: PathBuf::new(),
            base: base_map,
            tags: BTreeMap::new(),
        },
    );

    let mut vault = Vault {
        salt: salt.to_vec(),
        public_key,
        wrapped_master_dek: Entry { nonce, ciphertext },
        link_index: BTreeMap::new(),
        entries: group_entries,
        signature: vec![],
        file_path: Some(path.to_path_buf()),
    };
    vault.seal_integrity(&signing_key).unwrap();
    vault.save().unwrap();
    vault
}

#[test]
fn test_cli_git_setup_initializes_repo_and_attributes() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();

    let mut cmd = envseal_cmd(temp_path);
    cmd.arg("git-setup")
        .arg("--init")
        .assert()
        .success()
        .stdout(predicate::str::contains("git configuration successfull!!"));

    assert!(temp_path.join(".git").exists());

    let gitattributes = fs::read_to_string(temp_path.join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert!(gitattributes.contains("*.envseal merge=envseal diff=envseal"));

    let gitignore =
        fs::read_to_string(temp_path.join(".gitignore")).expect("Failed to read .gitignore");
    assert!(gitignore.contains(".envseal*.lock"));
}

#[test]
fn test_cli_diff_locked_fingerprint_and_tamper_warning() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");

    create_fixture_vault(
        &vault_file,
        "master_pass",
        &[("DATABASE_URL", "postgres://localhost:5432")],
    );

    // 1. Run textconv diff driver on a valid vault
    let mut cmd = envseal_cmd(temp_path);
    cmd.arg("diff")
        .arg(&vault_file)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "DATABASE_URL = <locked: reseal-fingerprint:",
        ))
        .stdout(predicate::str::contains("# Group: project"))
        .stdout(predicate::str::contains("[base]"));

    // 2. Invalidate signature while keeping MessagePack structure deserializable
    let mut vault = Vault::load_from_file(&vault_file).unwrap();
    vault.signature[0] ^= 0xFF;
    let binary = rmp_serde::to_vec(&vault).unwrap();
    fs::write(&vault_file, binary).unwrap();

    // 3. Verify driver reports integrity check failure
    let mut tampered_cmd = envseal_cmd(temp_path);
    tampered_cmd
        .arg("diff")
        .arg(&vault_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Integrity check FAILED"))
        .stdout(predicate::str::contains(
            "vault may be corrupted or tampered with",
        ));
}

#[test]
fn test_cli_zero_trust_token_read_and_export_flow() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");

    let vault = create_fixture_vault(
        &vault_file,
        "master_pass",
        &[
            ("STRIPE_KEY", "sk_test_12345"),
            ("INTERNAL_TOKEN", "super_secret"),
        ],
    );
    let keys = vault.unlock("master_pass").unwrap();

    let base_scope_dek = crypto::derive_scope_dek(&keys.master_dek, "project", BASE_TAG);
    let entry_key = crypto::derive_entry_key(&base_scope_dek, "STRIPE_KEY");

    let mut token_keys = HashMap::new();
    token_keys.insert("STRIPE_KEY".to_string(), Zeroizing::new(entry_key.to_vec()));

    let scope_str = vault.tag_scope(None, BASE_TAG).unwrap();
    let token = TokenManager::create(
        &keys.signing_key,
        &scope_str,
        token_keys,
        "ci-worker",
        Some(3600),
        Some("E2E Test Token"),
    )
    .unwrap();

    let token_file = temp_path.join("ci.token");
    fs::write(&token_file, token).unwrap();

    // Test `envseal get` via `--token-file`
    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("STRIPE_KEY")
        .arg("--token-file")
        .arg(&token_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("STRIPE_KEY: sk_test_12345"));

    // Key outside token scope must be rejected
    let mut get_denied_cmd = envseal_cmd(temp_path);
    get_denied_cmd
        .arg("get")
        .arg("INTERNAL_TOKEN")
        .arg("--token-file")
        .arg(&token_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("lacks permission to decrypt it"));

    // Test `envseal export` via `--token-file`
    let export_dest = temp_path.join("exported.env");
    let mut export_cmd = envseal_cmd(temp_path);
    export_cmd
        .arg("export")
        .arg("-o")
        .arg(&export_dest)
        .arg("--token-file")
        .arg(&token_file)
        .assert()
        .success();

    let exported_content = fs::read_to_string(&export_dest).unwrap();
    assert!(exported_content.contains("STRIPE_KEY=sk_test_12345"));
    assert!(!exported_content.contains("INTERNAL_TOKEN"));

    // Test `envseal load` evaluation output via `--token-file`
    let mut load_cmd = envseal_cmd(temp_path);
    load_cmd
        .arg("load")
        .arg("--token-file")
        .arg(&token_file)
        .env("SHELL", "/bin/bash")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "export STRIPE_KEY='sk_test_12345'",
        ));
}

#[test]
fn test_cli_three_way_merge_disjoint_fast_forward() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();

    let base_path = temp_path.join("base.envseal");
    let ours_path = temp_path.join("ours.envseal");
    let theirs_path = temp_path.join("theirs.envseal");

    // 1. Create common ancestor vault
    let base_v = create_fixture_vault(&base_path, "shared_pass", &[("COMMON", "initial")]);
    let keys = base_v.unlock("shared_pass").unwrap();

    // 2. Branch 'ours' introduces FEATURE_A on top of base
    let mut ours_v = base_v.clone();
    ours_v.file_path = Some(ours_path.clone());
    ours_v
        .set_entry(&keys, None, None, "FEATURE_A", "enabled", None)
        .unwrap();
    ours_v.save().unwrap();

    // 3. Branch 'theirs' introduces FEATURE_B on top of base
    let mut theirs_v = base_v.clone();
    theirs_v.file_path = Some(theirs_path.clone());
    theirs_v
        .set_entry(&keys, None, None, "FEATURE_B", "installed", None)
        .unwrap();
    theirs_v.save().unwrap();

    let askpass_path = create_askpass_script(temp_path);

    // Execute 3-way merge driver
    let mut merge_cmd = envseal_cmd(temp_path);
    merge_cmd
        .arg("merge")
        .arg("--base")
        .arg(&base_path)
        .arg("--ours")
        .arg(&ours_path)
        .arg("--theirs")
        .arg(&theirs_path)
        .env("ENVSEAL_PASSWORD", "shared_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Successfully merged and resealed vault",
        ));

    // Verify reconciled entries inside merged vault
    let merged_vault = Vault::load_from_file(&ours_path).unwrap();
    let merged_keys = merged_vault.unlock("shared_pass").unwrap();

    let val_common = merged_vault
        .get_entry(&merged_keys.master_dek, None, None, "COMMON", None)
        .unwrap();
    let val_a = merged_vault
        .get_entry(&merged_keys.master_dek, None, None, "FEATURE_A", None)
        .unwrap();
    let val_b = merged_vault
        .get_entry(&merged_keys.master_dek, None, None, "FEATURE_B", None)
        .unwrap();

    assert_eq!(val_common.as_str(), "initial");
    assert_eq!(val_a.as_str(), "enabled");
    assert_eq!(val_b.as_str(), "installed");
}

#[test]
fn test_cli_three_way_merge_conflict_strategy_resolution() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();

    let base_path = temp_path.join("base.envseal");
    let ours_path = temp_path.join("ours.envseal");
    let theirs_path = temp_path.join("theirs.envseal");

    // 1. Create common ancestor vault
    let base_v = create_fixture_vault(&base_path, "pass", &[("TIMEOUT", "30")]);
    let keys = base_v.unlock("pass").unwrap();

    // 2. Branch 'ours' modifies TIMEOUT to 60
    let mut ours_v = base_v.clone();
    ours_v.file_path = Some(ours_path.clone());
    ours_v
        .set_entry(&keys, None, None, "TIMEOUT", "60", None)
        .unwrap();
    ours_v.save().unwrap();

    // 3. Branch 'theirs' modifies TIMEOUT to 120 (conflicting modification)
    let mut theirs_v = base_v.clone();
    theirs_v.file_path = Some(theirs_path.clone());
    theirs_v
        .set_entry(&keys, None, None, "TIMEOUT", "120", None)
        .unwrap();
    theirs_v.save().unwrap();

    let askpass_path = create_askpass_script(temp_path);

    // Merge with default strategy (Fail) must exit with conflict error
    let mut fail_cmd = envseal_cmd(temp_path);
    fail_cmd
        .arg("merge")
        .arg("--base")
        .arg(&base_path)
        .arg("--ours")
        .arg(&ours_path)
        .arg("--theirs")
        .arg(&theirs_path)
        .env("ENVSEAL_PASSWORD", "pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Merge halted due to conflicts"));

    // Merge with `--strategy theirs` must pick 120
    let mut resolve_cmd = envseal_cmd(temp_path);
    resolve_cmd
        .arg("merge")
        .arg("--base")
        .arg(&base_path)
        .arg("--ours")
        .arg(&ours_path)
        .arg("--theirs")
        .arg(&theirs_path)
        .arg("--strategy")
        .arg("theirs")
        .env("ENVSEAL_PASSWORD", "pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .success();

    let resolved_v = Vault::load_from_file(&ours_path).unwrap();
    let res_keys = resolved_v.unlock("pass").unwrap();
    let timeout_val = resolved_v
        .get_entry(&res_keys.master_dek, None, None, "TIMEOUT", None)
        .unwrap();
    assert_eq!(timeout_val.as_str(), "120");
}

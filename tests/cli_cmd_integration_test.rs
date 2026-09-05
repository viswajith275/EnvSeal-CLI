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
                nonce: n.to_vec(),
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
        wrapped_master_dek: Entry {
            nonce: nonce.to_vec(),
            ciphertext,
        },
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
    cmd.arg("git-setup").arg("--init").assert().success();

    assert!(temp_path.join(".git").exists());
    let gitattributes = fs::read_to_string(temp_path.join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert!(gitattributes.contains("*.envseal merge=envseal"));

    let gitignore =
        fs::read_to_string(temp_path.join(".gitignore")).expect("Failed to read .gitignore");
    assert!(gitignore.contains(".envseal*.lock"));
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

    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("STRIPE_KEY")
        .arg("--token-file")
        .arg(&token_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("STRIPE_KEY: sk_test_12345"));

    let mut get_denied_cmd = envseal_cmd(temp_path);
    get_denied_cmd
        .arg("get")
        .arg("INTERNAL_TOKEN")
        .arg("--token-file")
        .arg(&token_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("lacks permission to decrypt it"));

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

    let base_v = create_fixture_vault(&base_path, "shared_pass", &[("COMMON", "initial")]);
    let keys = base_v.unlock("shared_pass").unwrap();

    let mut ours_v = base_v.clone();
    ours_v.file_path = Some(ours_path.clone());
    ours_v
        .set_entry(&keys, None, None, "FEATURE_A", "enabled", None)
        .unwrap();
    ours_v.save().unwrap();

    let mut theirs_v = base_v.clone();
    theirs_v.file_path = Some(theirs_path.clone());
    theirs_v
        .set_entry(&keys, None, None, "FEATURE_B", "installed", None)
        .unwrap();
    theirs_v.save().unwrap();

    let askpass_path = create_askpass_script(temp_path);
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

    let base_v = create_fixture_vault(&base_path, "pass", &[("TIMEOUT", "30")]);
    let keys = base_v.unlock("pass").unwrap();

    let mut ours_v = base_v.clone();
    ours_v.file_path = Some(ours_path.clone());
    ours_v
        .set_entry(&keys, None, None, "TIMEOUT", "60", None)
        .unwrap();
    ours_v.save().unwrap();

    let mut theirs_v = base_v.clone();
    theirs_v.file_path = Some(theirs_path.clone());
    theirs_v
        .set_entry(&keys, None, None, "TIMEOUT", "120", None)
        .unwrap();
    theirs_v.save().unwrap();

    let askpass_path = create_askpass_script(temp_path);
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

#[test]
fn test_cli_export_file_posix_permissions() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");
    let export_file = temp_path.join("sensitive.env");

    create_fixture_vault(&vault_file, "master_pass", &[("SECRET_KEY", "prod_key")]);

    let askpass_path = create_askpass_script(temp_path);
    let mut cmd = envseal_cmd(temp_path);
    cmd.arg("export")
        .arg("-o")
        .arg(&export_file)
        .env("ENVSEAL_PASSWORD", "master_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .success();

    assert!(export_file.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&export_file).unwrap().permissions();
        let mode = perms.mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Exported secrets file must have restrictive 0600 permissions, got: {:o}",
            mode
        );
    }
}

#[test]
fn test_cli_run_executes_child_with_injected_secrets() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");

    create_fixture_vault(
        &vault_file,
        "master_pass",
        &[("DYNAMIC_INJECTED_VAR", "injected_success")],
    );

    let askpass_path = create_askpass_script(temp_path);
    #[cfg(unix)]
    let (prog, args) = ("sh", vec!["-c", "echo $DYNAMIC_INJECTED_VAR"]);
    #[cfg(windows)]
    let (prog, args) = ("cmd.exe", vec!["/C", "echo %DYNAMIC_INJECTED_VAR%"]);

    let mut cmd = envseal_cmd(temp_path);
    cmd.arg("run")
        .arg("--")
        .arg(prog)
        .args(&args)
        .env("ENVSEAL_PASSWORD", "master_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("injected_success"));
}

#[test]
fn test_cli_remove_variable_flow() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");

    create_fixture_vault(
        &vault_file,
        "master_pass",
        &[("LIVE_API", "api_secret_val_999")],
    );

    let askpass_path = create_askpass_script(temp_path);

    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("LIVE_API")
        .env("ENVSEAL_PASSWORD", "master_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("api_secret_val_999"));

    let mut rm_cmd = envseal_cmd(temp_path);
    rm_cmd
        .arg("rm")
        .arg("LIVE_API")
        .arg("--force")
        .env("ENVSEAL_PASSWORD", "master_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .success();

    let mut verify_cmd = envseal_cmd(temp_path);
    verify_cmd
        .arg("get")
        .arg("LIVE_API")
        .env("ENVSEAL_PASSWORD", "master_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .failure();
}
#[test]
fn test_cli_import_validates_and_stores_dotenv() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");
    create_fixture_vault(&vault_file, "master_pass", &[]);
    let askpass_path = create_askpass_script(temp_path);

    let dotenv_file = temp_path.join("import.env");
    fs::write(
        &dotenv_file,
        "# Comment line\nVALID_KEY=hello_world\nINVALID-KEY=skip_me\nMULTILINE='line1\\nline2'\n",
    )
    .unwrap();

    let mut cmd = envseal_cmd(temp_path);
    cmd.arg("import")
        .arg(&dotenv_file)
        .env("ENVSEAL_PASSWORD", "master_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .success();

    // Verify stored entries via get
    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("VALID_KEY")
        .env("ENVSEAL_PASSWORD", "master_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));

    // Invalid shell keys must have been skipped
    let mut get_invalid_cmd = envseal_cmd(temp_path);
    get_invalid_cmd
        .arg("get")
        .arg("INVALID-KEY")
        .env("ENVSEAL_PASSWORD", "master_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .failure();
}

#[test]
fn test_cli_token_and_list_commands() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");
    create_fixture_vault(
        &vault_file,
        "master_pass",
        &[("AUTH_SECRET", "supersecret"), ("METRIC_PORT", "9090")],
    );
    let askpass_path = create_askpass_script(temp_path);

    // 1. Test `list`
    let mut list_cmd = envseal_cmd(temp_path);
    list_cmd
        .arg("list")
        .assert()
        .success()
        .stderr(predicate::str::contains("AUTH_SECRET"))
        .stderr(predicate::str::contains("METRIC_PORT"));

    // 2. Test `token` generation to a restricted file
    let token_dest = temp_path.join("agent.token");
    let mut token_cmd = envseal_cmd(temp_path);
    token_cmd
        .arg("token")
        .arg("--out")
        .arg(&token_dest)
        .arg("AUTH_SECRET")
        .env("ENVSEAL_PASSWORD", "master_pass")
        .env("GIT_ASKPASS", &askpass_path)
        .assert()
        .success();

    assert!(token_dest.exists());
    let token_str = fs::read_to_string(&token_dest).unwrap();
    assert!(token_str.starts_with("envseal_"));

    // Verify scoped execution with the newly generated token
    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("AUTH_SECRET")
        .arg("--token-file")
        .arg(&token_dest)
        .assert()
        .success()
        .stdout(predicate::str::contains("AUTH_SECRET: supersecret"));
}

#[test]
fn test_cli_passwd_rotates_master_authentication() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");
    create_fixture_vault(&vault_file, "old_password", &[("KEY", "persisted")]);

    // Create a helper askpass that switches to the new password for passwd prompts
    let script_path = temp_path.join("passwd_askpass.sh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(
            &script_path,
            r#"#!/bin/sh
case "$1" in
    *"new"*) printf 'new_password' ;;
    *) printf 'old_password' ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    {
        let mut passwd_cmd = envseal_cmd(temp_path);
        passwd_cmd
            .arg("passwd")
            .env("GIT_ASKPASS", &script_path)
            .assert()
            .success();

        // Old password must fail
        let askpass_old = create_askpass_script(temp_path);
        let mut old_cmd = envseal_cmd(temp_path);
        old_cmd
            .arg("get")
            .arg("KEY")
            .env("ENVSEAL_PASSWORD", "old_password")
            .env("GIT_ASKPASS", &askpass_old)
            .assert()
            .failure();

        // New password succeeds and decrypts preserved entry
        let mut new_cmd = envseal_cmd(temp_path);
        new_cmd
            .arg("get")
            .arg("KEY")
            .env("ENVSEAL_PASSWORD", "new_password")
            .env("GIT_ASKPASS", &askpass_old)
            .assert()
            .success()
            .stdout(predicate::str::contains("KEY: persisted"));
    }
}

#[test]
fn test_askpass_resolution_without_terminal() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut script = NamedTempFile::new().unwrap();
    writeln!(script, "#!/bin/sh\nprintf 'secret_123'").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(script.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    std::env::set_var("GIT_ASKPASS", script.path());
    let res = envseal::utils::unlock::prompt_with_fallback("password: ").unwrap();
    assert_eq!(&*res, "secret_123");
    std::env::remove_var("GIT_ASKPASS");
}
#[test]
fn test_change_password_leaves_no_active_session() {
    use envseal::utils::session::SessionManager;

    let temp = tempdir().expect("Failed to create tempdir");
    let vault_path = temp.path().join(".envseal");
    // reuses existing file fixture so save() has a valid disk target; upgrade path: in-memory mock backend
    let mut vault = create_fixture_vault(&vault_path, "initial", &[]);
    let keys = vault.unlock("initial").unwrap();

    vault.change_master_password(&keys, "updated_pass").unwrap();
    assert!(SessionManager::get_active_keys(&vault.master_scope())
        .unwrap()
        .is_none());
}

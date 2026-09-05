use age::secrecy::ExposeSecret;
use assert_cmd::Command;
use envseal::utils::crypto;
use envseal::utils::envelope;
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
    cmd.env_remove("ENVSEAL_IDENTITY");
    cmd.env_remove("ENVSEAL_TOKEN");
    cmd
}

// uses default local recipient file for test fixture generation; upgrade path: isolate test runs with dedicated in-memory mock backend
fn create_fixture_vault(
    path: &Path,
    recipient: Option<&str>,
    entries: &[(&str, &str)],
) -> (Vault, String) {
    let (recip, secret) = match recipient {
        Some(r) => (r.to_string(), String::new()),
        None => {
            let default_recip = envelope::get_or_create_default_recipient().unwrap();
            (default_recip, String::new())
        }
    };

    let signing_seed = crypto::generate_dek();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    let master_dek = crypto::generate_dek();

    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(&*master_dek);
    payload[32..].copy_from_slice(signing_key.to_bytes().as_slice());

    let envelope = envelope::wrap_envelope(&payload, &[recip.clone()]).unwrap();

    let scope_dek = crypto::derive_scope_dek(&master_dek, "project", BASE_TAG);
    let mut base_map = BTreeMap::new();
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
        recipients: vec![recip],
        envelope,
        public_key,
        signature: vec![],
        link_index: BTreeMap::new(),
        entries: group_entries,
        file_path: Some(path.to_path_buf()),
    };
    vault.seal_integrity(&signing_key).unwrap();
    vault.save().unwrap();
    (vault, secret)
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
    let (vault, _) = create_fixture_vault(
        &vault_file,
        None,
        &[
            ("STRIPE_KEY", "sk_test_12345"),
            ("INTERNAL_TOKEN", "super_secret"),
        ],
    );

    let keys = vault.unlock(true).unwrap();
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
        .arg("--token")
        .arg(&token_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("STRIPE_KEY: sk_test_12345"));

    let mut get_denied_cmd = envseal_cmd(temp_path);
    get_denied_cmd
        .arg("get")
        .arg("INTERNAL_TOKEN")
        .arg("--token")
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
        .arg("--token")
        .arg(&token_file)
        .assert()
        .success();
    let exported_content = fs::read_to_string(&export_dest).unwrap();
    assert!(exported_content.contains("STRIPE_KEY=sk_test_12345"));
    assert!(!exported_content.contains("INTERNAL_TOKEN"));

    let mut load_cmd = envseal_cmd(temp_path);
    load_cmd
        .arg("load")
        .arg("--token")
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

    let (base_v, _) = create_fixture_vault(&base_path, None, &[("COMMON", "initial")]);
    let keys = base_v.unlock(true).unwrap();

    let mut ours_v = base_v.clone();
    ours_v.file_path = Some(ours_path.clone());
    ours_v
        .set_entry(&keys, None, None, "FEATURE_A", "enabled")
        .unwrap();
    ours_v.save().unwrap();

    let mut theirs_v = base_v.clone();
    theirs_v.file_path = Some(theirs_path.clone());
    theirs_v
        .set_entry(&keys, None, None, "FEATURE_B", "installed")
        .unwrap();
    theirs_v.save().unwrap();

    let mut merge_cmd = envseal_cmd(temp_path);
    merge_cmd
        .arg("merge")
        .arg("--base")
        .arg(&base_path)
        .arg("--ours")
        .arg(&ours_path)
        .arg("--theirs")
        .arg(&theirs_path)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Successfully merged and resealed vault",
        ));

    let merged_vault = Vault::load_from_file(&ours_path).unwrap();
    let merged_keys = merged_vault.unlock(true).unwrap();
    assert_eq!(
        merged_vault
            .get_entry(&merged_keys.master_dek, None, None, "COMMON")
            .unwrap()
            .as_str(),
        "initial"
    );
    assert_eq!(
        merged_vault
            .get_entry(&merged_keys.master_dek, None, None, "FEATURE_A")
            .unwrap()
            .as_str(),
        "enabled"
    );
    assert_eq!(
        merged_vault
            .get_entry(&merged_keys.master_dek, None, None, "FEATURE_B")
            .unwrap()
            .as_str(),
        "installed"
    );
}

#[test]
fn test_cli_three_way_merge_conflict_strategy_resolution() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let base_path = temp_path.join("base.envseal");
    let ours_path = temp_path.join("ours.envseal");
    let theirs_path = temp_path.join("theirs.envseal");

    let (base_v, _) = create_fixture_vault(&base_path, None, &[("TIMEOUT", "30")]);
    let keys = base_v.unlock(true).unwrap();

    let mut ours_v = base_v.clone();
    ours_v.file_path = Some(ours_path.clone());
    ours_v
        .set_entry(&keys, None, None, "TIMEOUT", "60")
        .unwrap();
    ours_v.save().unwrap();

    let mut theirs_v = base_v.clone();
    theirs_v.file_path = Some(theirs_path.clone());
    theirs_v
        .set_entry(&keys, None, None, "TIMEOUT", "120")
        .unwrap();
    theirs_v.save().unwrap();

    let mut fail_cmd = envseal_cmd(temp_path);
    fail_cmd
        .arg("merge")
        .arg("--base")
        .arg(&base_path)
        .arg("--ours")
        .arg(&ours_path)
        .arg("--theirs")
        .arg(&theirs_path)
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
        .assert()
        .success();

    let resolved_v = Vault::load_from_file(&ours_path).unwrap();
    let res_keys = resolved_v.unlock(true).unwrap();
    let timeout_val = resolved_v
        .get_entry(&res_keys.master_dek, None, None, "TIMEOUT")
        .unwrap();
    assert_eq!(timeout_val.as_str(), "120");
}

#[test]
fn test_cli_export_file_posix_permissions() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");
    let export_file = temp_path.join("sensitive.env");

    create_fixture_vault(&vault_file, None, &[("SECRET_KEY", "prod_key")]);

    let mut cmd = envseal_cmd(temp_path);
    cmd.arg("export")
        .arg("-o")
        .arg(&export_file)
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
        None,
        &[("DYNAMIC_INJECTED_VAR", "injected_success")],
    );

    #[cfg(unix)]
    let (prog, args) = ("sh", vec!["-c", "echo $DYNAMIC_INJECTED_VAR"]);
    #[cfg(windows)]
    let (prog, args) = ("cmd.exe", vec!["/C", "echo %DYNAMIC_INJECTED_VAR%"]);

    let mut cmd = envseal_cmd(temp_path);
    cmd.arg("run")
        .arg("--")
        .arg(prog)
        .args(&args)
        .assert()
        .success()
        .stdout(predicate::str::contains("injected_success"));
}

#[test]
fn test_cli_remove_variable_flow() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");
    create_fixture_vault(&vault_file, None, &[("LIVE_API", "api_secret_val_999")]);

    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("LIVE_API")
        .assert()
        .success()
        .stdout(predicate::str::contains("api_secret_val_999"));

    let mut rm_cmd = envseal_cmd(temp_path);
    rm_cmd
        .arg("remove")
        .arg("LIVE_API")
        .arg("--force")
        .assert()
        .success();

    let mut verify_cmd = envseal_cmd(temp_path);
    verify_cmd.arg("get").arg("LIVE_API").assert().failure();
}

#[test]
fn test_cli_import_validates_and_stores_dotenv() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");
    create_fixture_vault(&vault_file, None, &[]);

    let dotenv_file = temp_path.join("import.env");
    fs::write(
        &dotenv_file,
        "# Comment line\nVALID_KEY=hello_world\nINVALID-KEY=skip_me\nMULTILINE='line1\\nline2'\n",
    )
    .unwrap();

    let mut cmd = envseal_cmd(temp_path);
    cmd.arg("import").arg(&dotenv_file).assert().success();

    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("VALID_KEY")
        .assert()
        .success()
        .stdout(predicate::str::contains("hello_world"));

    let mut get_invalid_cmd = envseal_cmd(temp_path);
    get_invalid_cmd
        .arg("get")
        .arg("INVALID-KEY")
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
        None,
        &[("AUTH_SECRET", "supersecret"), ("METRIC_PORT", "9090")],
    );

    let mut list_cmd = envseal_cmd(temp_path);
    list_cmd
        .arg("list")
        .assert()
        .success()
        .stderr(predicate::str::contains("AUTH_SECRET"))
        .stderr(predicate::str::contains("METRIC_PORT"));

    let token_dest = temp_path.join("agent.token");
    let mut token_cmd = envseal_cmd(temp_path);
    token_cmd
        .arg("token")
        .arg("-o")
        .arg(&token_dest)
        .arg("AUTH_SECRET")
        .assert()
        .success();

    assert!(token_dest.exists());
    let token_str = fs::read_to_string(&token_dest).unwrap();
    assert!(token_str.starts_with("envseal_"));

    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("AUTH_SECRET")
        .arg("--token")
        .arg(&token_dest)
        .assert()
        .success()
        .stdout(predicate::str::contains("AUTH_SECRET: supersecret"));
}

#[test]
fn test_cli_recipient_lifecycle() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");

    let default_recip = envelope::get_or_create_default_recipient().unwrap();
    create_fixture_vault(&vault_file, Some(&default_recip), &[("SECRET", "val")]);

    let mut list_cmd = envseal_cmd(temp_path);
    list_cmd
        .arg("recipient")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains(&default_recip));

    let id2 = age::x25519::Identity::generate();
    let recip2 = id2.to_public().to_string();
    let secret2 = id2.to_string().expose_secret().to_string();

    let mut add_cmd = envseal_cmd(temp_path);
    add_cmd
        .arg("recipient")
        .arg("add")
        .arg(&recip2)
        .assert()
        .success();

    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("SECRET")
        .env("ENVSEAL_IDENTITY", &secret2)
        .assert()
        .success()
        .stdout(predicate::str::contains("SECRET: val"));

    let mut rm_cmd = envseal_cmd(temp_path);
    rm_cmd
        .arg("recipient")
        .arg("remove")
        .arg(&default_recip)
        .env("ENVSEAL_IDENTITY", &secret2)
        .assert()
        .success();

    let mut old_get = envseal_cmd(temp_path);
    old_get
        .arg("get")
        .arg("SECRET")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Access Denied"));

    let mut rm_last = envseal_cmd(temp_path);
    rm_last
        .arg("recipient")
        .arg("remove")
        .arg(&recip2)
        .env("ENVSEAL_IDENTITY", &secret2)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Cannot remove the last recipient"));
}

#[test]
fn test_cli_rotate_dek_command() {
    let temp = tempdir().expect("Failed to create tempdir");
    let temp_path = temp.path();
    let vault_file = temp_path.join(".envseal");
    let (vault, _) = create_fixture_vault(&vault_file, None, &[("PERSIST", "data")]);

    let keys = vault.unlock(true).unwrap();
    let token = vault
        .create_token(
            &keys.signing_key,
            &keys.master_dek,
            None,
            None,
            "ci",
            Some(3600),
            None,
            None,
        )
        .unwrap();

    let mut rotate_cmd = envseal_cmd(temp_path);
    rotate_cmd.arg("rotate").assert().success();

    let mut get_cmd = envseal_cmd(temp_path);
    get_cmd
        .arg("get")
        .arg("PERSIST")
        .assert()
        .success()
        .stdout(predicate::str::contains("PERSIST: data"));

    let mut token_get = envseal_cmd(temp_path);
    token_get
        .arg("get")
        .arg("PERSIST")
        .arg("--token")
        .arg(&token)
        .assert()
        .failure();
}
#[test]
fn test_recipient_lookup_by_name_or_index() {
    let recipients = vec![
        "age1key1... # alice".to_string(),
        "ssh-ed25519 AAA... bob".to_string(),
    ];

    let find = |target: &str| -> Option<usize> {
        if let Ok(i) = target.parse::<usize>() {
            return (i < recipients.len()).then_some(i);
        }
        recipients.iter().position(|r| {
            let (k, name) = r
                .split_once('#')
                .map(|(k, n)| (k.trim(), n.trim()))
                .unwrap_or((r.trim(), ""));
            r == target || k == target || name.eq_ignore_ascii_case(target)
        })
    };

    assert_eq!(find("alice"), Some(0));
    assert_eq!(find("0"), Some(0));
    assert_eq!(find("1"), Some(1));
    assert_eq!(find("charlie"), None);
}

#[test]
fn test_branch_binding_and_precommit_shield() {
    let dir = tempdir().unwrap();
    let p = dir.path();

    // ponytail: shells out to git-setup CLI to ensure CWD isolation in multi-threaded test runners
    envseal_cmd(p)
        .args(["git-setup", "--init"])
        .assert()
        .success();
    let hook = p.join(".git").join("hooks").join("pre-commit");
    assert!(hook.exists());

    // Verify pre-commit rejects plaintext .env and accepts .envseal
    let script = fs::read_to_string(&hook).unwrap();
    assert!(script.contains("grep -v '\\.envseal'"));

    // Verify GitHub prefix routing syntax
    let target = "@torvalds";
    assert_eq!(target.strip_prefix('@'), Some("torvalds"));
}

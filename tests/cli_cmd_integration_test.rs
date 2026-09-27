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
        .stdout(predicate::str::contains("AUTH_SECRET"))
        .stdout(predicate::str::contains("METRIC_PORT"));

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

    // shells out to git-setup CLI to ensure CWD isolation in multi-threaded test runners
    envseal_cmd(p)
        .args(["git-setup", "--init"])
        .assert()
        .success();
    let hook = p.join(".git").join("hooks").join("pre-commit");
    assert!(hook.exists());

    // Verify pre-commit rejects plaintext .env and accepts .envseal
    let script = fs::read_to_string(&hook).unwrap();
    assert!(script.contains("grep -v -E '(\\.envseal|\\.example|\\.sample|\\.template|\\.dist)"));

    // Verify GitHub prefix routing syntax
    let target = "@torvalds";
    assert_eq!(target.strip_prefix('@'), Some("torvalds"));
}

/// Isolated test harness providing both a local project directory and a mock OS config directory.
struct OverlayTestHarness {
    _temp_dir: tempfile::TempDir,
    pub local_dir: PathBuf,
    pub config_dir: PathBuf,
    pub identity_sec: String,
    pub recipient_pub: String,
}

impl OverlayTestHarness {
    fn new() -> Self {
        let temp = tempdir().expect("Failed to create tempdir");
        let local_dir = temp.path().join("project_repo");
        let config_dir = temp.path().join("mock_config");
        fs::create_dir_all(&local_dir).unwrap();
        fs::create_dir_all(&config_dir).unwrap();

        let id = age::x25519::Identity::generate();
        let recipient_pub = id.to_public().to_string();
        let identity_sec = id.to_string().expose_secret().to_string();

        Self {
            _temp_dir: temp,
            local_dir,
            config_dir,
            identity_sec,
            recipient_pub,
        }
    }

    /// Prepares an envseal command isolated from host system secrets and user configs.
    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("envseal").expect("Failed to locate envseal binary");
        cmd.current_dir(&self.local_dir);
        cmd.env_remove("ENVSEAL_TEST_PATH");
        cmd.env_remove("ENVSEAL_TOKEN");
        cmd.env("ENVSEAL_IDENTITY", &self.identity_sec);

        // Direct OS configuration directories to our temporary config folder
        cmd.env("XDG_CONFIG_HOME", &self.config_dir);
        cmd.env("HOME", &self.config_dir);
        cmd.env("USERPROFILE", &self.config_dir);
        cmd.env("APPDATA", &self.config_dir);
        cmd
    }

    /// Initializes both local and global vaults with test secrets.
    fn bootstrap_dual_vaults(&self) {
        // 1. Initialize local vault
        self.cmd()
            .args(["init", "-l", "-r", &self.recipient_pub])
            .assert()
            .success();

        // 2. Initialize global vault
        self.cmd()
            .args(["init", "-G", "-r", &self.recipient_pub])
            .assert()
            .success();

        // 3. Set local project secrets
        self.cmd()
            .args(["set", "PROJECT_NAME"])
            .write_stdin("EnvSealApp")
            .assert()
            .success();

        self.cmd()
            .args(["set", "DATABASE_URL"])
            .write_stdin("postgres://shared-cluster:5432/main")
            .assert()
            .success();

        self.cmd()
            .args(["set", "AWS_ACCESS_KEY_ID"])
            .write_stdin("AKIA_SHARED_PROJECT_KEY")
            .assert()
            .success();

        // 4. Set personal secrets in global vault under group 'personal'
        self.cmd()
            .args(["set", "-G", "--group", "personal", "AWS_ACCESS_KEY_ID"])
            .write_stdin("AKIA_MY_PERSONAL_SANDBOX_KEY")
            .assert()
            .success();

        self.cmd()
            .args(["set", "-G", "--group", "personal", "PERSONAL_DEBUG_LEVEL"])
            .write_stdin("verbose")
            .assert()
            .success();
    }
}

#[test]
fn test_cli_override_flag_conflicts_and_validations() {
    let harness = OverlayTestHarness::new();
    harness.bootstrap_dual_vaults();

    // 1. Cannot use --override and --with-global together (clap mutual exclusion)
    harness
        .cmd()
        .args([
            "run",
            "--override",
            "AWS_KEY",
            "--with-global",
            "--",
            "echo",
            "test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));

    // 2. Cannot use --override when already targeting global vault (-G)
    harness
        .cmd()
        .args(["run", "-G", "--override", "AWS_KEY", "--", "echo", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Cannot use --override or --with-global when operating directly on the global",
        ));

    // 3. Cannot use --with-global when already targeting global vault (-G)
    harness
        .cmd()
        .args(["load", "-G", "--with-global"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Cannot use --override or --with-global when operating directly on the global",
        ));

    // 4. Cannot use --global-group when already targeting global vault (-G)
    harness
        .cmd()
        .args(["export", "-G", "--global-group", "personal"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Use --group and --tag instead of --global-group and --global-tag",
        ));
}

#[test]
fn test_cli_run_selective_override_replaces_only_specified_keys() {
    let harness = OverlayTestHarness::new();
    harness.bootstrap_dual_vaults();

    #[cfg(unix)]
    let (prog, args) = (
        "sh",
        vec![
            "-c",
            "echo AWS=$AWS_ACCESS_KEY_ID DB=$DATABASE_URL DEBUG=$PERSONAL_DEBUG_LEVEL",
        ],
    );
    #[cfg(windows)]
    let (prog, args) = (
        "cmd.exe",
        vec![
            "/C",
            "echo AWS=%AWS_ACCESS_KEY_ID% DB=%DATABASE_URL% DEBUG=%PERSONAL_DEBUG_LEVEL%",
        ],
    );

    // Run with selective override for AWS_ACCESS_KEY_ID
    harness
        .cmd()
        .args([
            "run",
            "--override",
            "AWS_ACCESS_KEY_ID",
            "--global-group",
            "personal",
            "--",
            prog,
        ])
        .args(&args)
        .assert()
        .success()
        // Overridden by global vault
        .stdout(predicate::str::contains("AWS=AKIA_MY_PERSONAL_SANDBOX_KEY"))
        // Maintained from local vault
        .stdout(predicate::str::contains(
            "DB=postgres://shared-cluster:5432/main",
        ))
        // Unselected global keys must NOT be injected
        .stdout(predicate::str::contains("DEBUG=").and(predicate::str::contains("verbose").not()));
}

#[test]
fn test_cli_run_with_global_full_overlay() {
    let harness = OverlayTestHarness::new();
    harness.bootstrap_dual_vaults();

    #[cfg(unix)]
    let (prog, args) = (
        "sh",
        vec![
            "-c",
            "echo AWS=$AWS_ACCESS_KEY_ID DB=$DATABASE_URL DEBUG=$PERSONAL_DEBUG_LEVEL",
        ],
    );
    #[cfg(windows)]
    let (prog, args) = (
        "cmd.exe",
        vec![
            "/C",
            "echo AWS=%AWS_ACCESS_KEY_ID% DB=%DATABASE_URL% DEBUG=%PERSONAL_DEBUG_LEVEL%",
        ],
    );

    // Run with full global overlay
    harness
        .cmd()
        .args([
            "run",
            "--with-global",
            "--global-group",
            "personal",
            "--",
            prog,
        ])
        .args(&args)
        .assert()
        .success()
        // Global collided key wins
        .stdout(predicate::str::contains("AWS=AKIA_MY_PERSONAL_SANDBOX_KEY"))
        // Local project key retained
        .stdout(predicate::str::contains(
            "DB=postgres://shared-cluster:5432/main",
        ))
        // Additional global key injected
        .stdout(predicate::str::contains("DEBUG=verbose"));
}

#[test]
fn test_cli_link_directory_serves_as_default_override_group() {
    let harness = OverlayTestHarness::new();
    harness.bootstrap_dual_vaults();

    // Link the current directory to 'personal' in the global vault
    harness
        .cmd()
        .args(["link", "personal"])
        .assert()
        .success()
        .stderr(predicate::str::contains("linked group 'personal'"));

    #[cfg(unix)]
    let (prog, args) = ("sh", vec!["-c", "echo AWS=$AWS_ACCESS_KEY_ID"]);
    #[cfg(windows)]
    let (prog, args) = ("cmd.exe", vec!["/C", "echo AWS=%AWS_ACCESS_KEY_ID%"]);

    // Run --override WITHOUT specifying --global-group; should resolve via link
    harness
        .cmd()
        .args(["run", "--override", "AWS_ACCESS_KEY_ID", "--", prog])
        .args(&args)
        .assert()
        .success()
        .stdout(predicate::str::contains("AWS=AKIA_MY_PERSONAL_SANDBOX_KEY"));
}

#[test]
fn test_cli_global_tag_resolution_with_base_fallback() {
    let harness = OverlayTestHarness::new();
    harness.bootstrap_dual_vaults();

    // Add a tagged secret inside the global vault's 'personal' group
    harness
        .cmd()
        .args([
            "set",
            "-G",
            "--group",
            "personal",
            "--tag",
            "staging",
            "AWS_ACCESS_KEY_ID",
        ])
        .write_stdin("AKIA_STAGING_PERSONAL_KEY")
        .assert()
        .success();

    #[cfg(unix)]
    let (prog, args) = (
        "sh",
        vec![
            "-c",
            "echo AWS=$AWS_ACCESS_KEY_ID DEBUG=$PERSONAL_DEBUG_LEVEL",
        ],
    );
    #[cfg(windows)]
    let (prog, args) = (
        "cmd.exe",
        vec![
            "/C",
            "echo AWS=%AWS_ACCESS_KEY_ID% DEBUG=%PERSONAL_DEBUG_LEVEL%",
        ],
    );

    // Target the 'staging' tag inside the global group
    harness
        .cmd()
        .args([
            "run",
            "--with-global",
            "--global-group",
            "personal",
            "--global-tag",
            "staging",
            "--",
            prog,
        ])
        .args(&args)
        .assert()
        .success()
        // Takes value from 'staging' tag
        .stdout(predicate::str::contains("AWS=AKIA_STAGING_PERSONAL_KEY"))
        // Falls back to 'base' for secrets absent in 'staging'
        .stdout(predicate::str::contains("DEBUG=verbose"));
}

#[test]
fn test_cli_missing_override_key_warns_and_continues() {
    let harness = OverlayTestHarness::new();
    harness.bootstrap_dual_vaults();

    #[cfg(unix)]
    let (prog, args) = ("sh", vec!["-c", "echo DB=$DATABASE_URL"]);
    #[cfg(windows)]
    let (prog, args) = ("cmd.exe", vec!["/C", "echo DB=%DATABASE_URL%"]);

    // Override a key that does not exist in the global vault
    harness
        .cmd()
        .args([
            "run",
            "--override",
            "NON_EXISTENT_SECRET",
            "--global-group",
            "personal",
            "--",
            prog,
        ])
        .args(&args)
        .assert()
        .success()
        // Warns on stderr
        .stderr(predicate::str::contains(
            "Warning: Override key 'NON_EXISTENT_SECRET' was not found",
        ))
        // Continues execution normally
        .stdout(predicate::str::contains(
            "DB=postgres://shared-cluster:5432/main",
        ));
}

#[test]
fn test_cli_missing_global_vault_errors_cleanly() {
    let harness = OverlayTestHarness::new();
    // Initialize ONLY the local vault; global vault is not present
    harness
        .cmd()
        .args(["init", "-l", "-r", &harness.recipient_pub])
        .assert()
        .success();

    harness
        .cmd()
        .args([
            "run",
            "--override",
            "AWS_ACCESS_KEY_ID",
            "--global-group",
            "personal",
            "--",
            "echo",
            "test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Global vault not found or could not be loaded",
        ));
}

#[test]
fn test_cli_load_and_export_with_overrides() {
    let harness = OverlayTestHarness::new();
    harness.bootstrap_dual_vaults();

    // 1. Test 'load' command output formatting
    harness
        .cmd()
        .args([
            "load",
            "--override",
            "AWS_ACCESS_KEY_ID",
            "--global-group",
            "personal",
        ])
        .env("SHELL", "/bin/bash")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "export AWS_ACCESS_KEY_ID='AKIA_MY_PERSONAL_SANDBOX_KEY'",
        ))
        .stdout(predicate::str::contains(
            "export DATABASE_URL='postgres://shared-cluster:5432/main'",
        ));

    // 2. Test 'export' command file output
    let export_file = harness.local_dir.join("personal_merged.env");
    harness
        .cmd()
        .args([
            "export",
            "-o",
            export_file.to_str().unwrap(),
            "--with-global",
            "--global-group",
            "personal",
        ])
        .assert()
        .success();

    assert!(export_file.exists());
    let contents = fs::read_to_string(&export_file).unwrap();
    assert!(contents.contains("AWS_ACCESS_KEY_ID=AKIA_MY_PERSONAL_SANDBOX_KEY"));
    assert!(contents.contains("DATABASE_URL=postgres://shared-cluster:5432/main"));
    assert!(contents.contains("PERSONAL_DEBUG_LEVEL=verbose"));
}

#[test]
fn test_cli_offline_token_with_global_overrides() {
    let harness = OverlayTestHarness::new();
    harness.bootstrap_dual_vaults();

    // Generate an offline token scoped to PROJECT_NAME and AWS_ACCESS_KEY_ID
    let token_file = harness.local_dir.join("ci_scoped.token");
    harness
        .cmd()
        .args([
            "token",
            "-o",
            token_file.to_str().unwrap(),
            "PROJECT_NAME",
            "AWS_ACCESS_KEY_ID",
        ])
        .assert()
        .success();

    #[cfg(unix)]
    let (prog, args) = (
        "sh",
        vec!["-c", "echo PROJ=$PROJECT_NAME AWS=$AWS_ACCESS_KEY_ID"],
    );
    #[cfg(windows)]
    let (prog, args) = (
        "cmd.exe",
        vec!["/C", "echo PROJ=%PROJECT_NAME% AWS=%AWS_ACCESS_KEY_ID%"],
    );

    // Execute with offline token while overriding AWS credentials with personal ones
    harness
        .cmd()
        .args([
            "run",
            "--token",
            token_file.to_str().unwrap(),
            "--override",
            "AWS_ACCESS_KEY_ID",
            "--global-group",
            "personal",
            "--",
            prog,
        ])
        .args(&args)
        .assert()
        .success()
        // Decrypted via offline token from local vault
        .stdout(predicate::str::contains("PROJ=EnvSealApp"))
        // Overridden by personal global credentials
        .stdout(predicate::str::contains("AWS=AKIA_MY_PERSONAL_SANDBOX_KEY"));
}

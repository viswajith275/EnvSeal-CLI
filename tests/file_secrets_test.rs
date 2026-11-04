use age::secrecy::ExposeSecret;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};

struct FileTestHarness {
    _temp_dir: TempDir,
    pub local_dir: PathBuf,
    pub config_dir: PathBuf,
    pub identity_sec: String,
    pub recipient_pub: String,
}

impl FileTestHarness {
    fn new() -> Self {
        Self::with_recipient(None)
    }

    fn with_recipient(custom_recipient: Option<&str>) -> Self {
        let temp = tempdir().expect("Failed to create tempdir");
        let local_dir = temp.path().join("project");
        let config_dir = temp.path().join("config");
        fs::create_dir_all(&local_dir).unwrap();
        fs::create_dir_all(&config_dir).unwrap();

        let id = age::x25519::Identity::generate();
        let recipient_pub = id.to_public().to_string();
        let identity_sec = id.to_string().expose_secret().to_string();

        let harness = Self {
            _temp_dir: temp,
            local_dir,
            config_dir,
            identity_sec,
            recipient_pub,
        };

        harness
            .cmd()
            .args(["init", "-l", "-r", &harness.recipient_pub])
            .assert()
            .success();

        if let Some(r) = custom_recipient {
            harness
                .cmd()
                .args(["recipient", "add", r])
                .assert()
                .success();
        }

        harness
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("envseal").expect("Failed to locate envseal binary");
        cmd.current_dir(&self.local_dir);
        cmd.env_remove("ENVSEAL_TEST_PATH");
        cmd.env_remove("ENVSEAL_TOKEN");
        cmd.env("ENVSEAL_IDENTITY", &self.identity_sec);
        cmd.env("XDG_CONFIG_HOME", &self.config_dir);
        cmd.env("HOME", &self.config_dir);
        cmd.env("USERPROFILE", &self.config_dir);
        cmd.env("APPDATA", &self.config_dir);
        cmd
    }
}

#[test]
fn test_file_secret_set_and_get_out_roundtrip() {
    let harness = FileTestHarness::new();

    let cert_content =
        b"-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAP\n-----END CERTIFICATE-----\n";
    let cert_path = harness.local_dir.join("tls.crt");
    fs::write(&cert_path, cert_content).unwrap();

    harness
        .cmd()
        .args([
            "set",
            "TLS_CERT",
            "--file",
            cert_path.to_str().unwrap(),
            "--env-var",
            "CUSTOM_CERT_PATH",
        ])
        .assert()
        .success();

    // Verify list output shows file secret mapping
    harness
        .cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("TLS_CERT"));

    // Extract file secret to destination path
    let extracted_path = harness.local_dir.join("extracted.crt");
    harness
        .cmd()
        .args(["get", "TLS_CERT", "-o", extracted_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Extracted file secret 'TLS_CERT' ($CUSTOM_CERT_PATH)",
        ));

    let extracted_bytes = fs::read(&extracted_path).unwrap();
    assert_eq!(extracted_bytes, cert_content);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&extracted_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}

#[test]
fn test_file_secret_default_env_var_when_omitted() {
    let harness = FileTestHarness::new();

    let secret_data = b"{\"database\": \"postgres://localhost/prod\"}";
    let secret_path = harness.local_dir.join("db.json");
    fs::write(&secret_path, secret_data).unwrap();

    // Do not pass --env-var; should default to key name (DB_CONFIG)
    harness
        .cmd()
        .args(["set", "DB_CONFIG", "--file", secret_path.to_str().unwrap()])
        .assert()
        .success();

    let extracted_path = harness.local_dir.join("extracted_db.json");
    harness
        .cmd()
        .args(["get", "DB_CONFIG", "-o", extracted_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Extracted file secret 'DB_CONFIG' ($DB_CONFIG)",
        ));

    assert_eq!(fs::read(&extracted_path).unwrap(), secret_data);
}

#[test]
fn test_file_secret_piped_stdout() {
    let harness = FileTestHarness::new();

    let binary_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42];
    let binary_path = harness.local_dir.join("blob.bin");
    fs::write(&binary_path, &binary_data).unwrap();

    harness
        .cmd()
        .args(["set", "BLOB", "--file", binary_path.to_str().unwrap()])
        .assert()
        .success();

    // Piped stdout (non-terminal) receives exact bytes
    let output = harness.cmd().args(["get", "BLOB"]).assert().success();

    assert_eq!(output.get_output().stdout, binary_data);
}

#[test]
fn test_file_secret_run_injection_and_cleanup() {
    let harness = FileTestHarness::new();

    // Set normal text secret
    harness
        .cmd()
        .args(["set", "SERVICE_PORT"])
        .write_stdin("9000")
        .assert()
        .success();

    // Set file secret
    let token_data = b"ultra-secret-service-token-contents";
    let token_file = harness.local_dir.join("token.txt");
    fs::write(&token_file, token_data).unwrap();

    harness
        .cmd()
        .args([
            "set",
            "SVC_AUTH",
            "--file",
            token_file.to_str().unwrap(),
            "--env-var",
            "SVC_AUTH_FILE",
        ])
        .assert()
        .success();

    // Script to verify both text and file secrets injected at runtime
    let script = r#"
        echo "PORT=$SERVICE_PORT"
        echo "TOKEN_PATH=$SVC_AUTH_FILE"
        if [ ! -f "$SVC_AUTH_FILE" ]; then
            echo "ERROR: file secret missing"
            exit 2
        fi
        cat "$SVC_AUTH_FILE"
    "#;

    let output = harness
        .cmd()
        .args(["run", "--", "sh", "-c", script])
        .assert()
        .success()
        .stdout(predicate::str::contains("PORT=9000"))
        .stdout(predicate::str::contains(
            "ultra-secret-service-token-contents",
        ));

    // Extract the temp file path printed by the script and verify it was deleted after run
    let stdout_str = String::from_utf8_lossy(&output.get_output().stdout);
    for line in stdout_str.lines() {
        if let Some(path_str) = line.strip_prefix("TOKEN_PATH=") {
            let temp_path = Path::new(path_str.trim());
            assert!(
                !temp_path.exists(),
                "Temporary secret file should be removed after process exit: {}",
                path_str
            );
        }
    }
}

#[test]
fn test_file_secret_export_skips_with_warning() {
    let harness = FileTestHarness::new();

    harness
        .cmd()
        .args(["set", "NORMAL_VAR"])
        .write_stdin("hello_world")
        .assert()
        .success();

    let cert_path = harness.local_dir.join("ca.crt");
    fs::write(&cert_path, b"CA_CERT_BYTES").unwrap();
    harness
        .cmd()
        .args([
            "set",
            "CA_FILE",
            "--file",
            cert_path.to_str().unwrap(),
            "--env-var",
            "CA_BUNDLE",
        ])
        .assert()
        .success();

    let export_dest = harness.local_dir.join("exported.env");
    harness
        .cmd()
        .args(["export", "-o", export_dest.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: Skipping file secret 'CA_FILE' ($CA_BUNDLE)",
        ))
        .stderr(predicate::str::contains(
            "Successfully exported 1 variable(s)",
        ));

    let content = fs::read_to_string(&export_dest).unwrap();
    assert!(content.contains("NORMAL_VAR=hello_world"));
    assert!(!content.contains("CA_FILE"));
    assert!(!content.contains("CA_BUNDLE"));
}

#[test]
fn test_file_secret_load_skips_file_secret() {
    let harness = FileTestHarness::new();

    harness
        .cmd()
        .args(["set", "APP_ENV"])
        .write_stdin("production")
        .assert()
        .success();

    let key_path = harness.local_dir.join("id_rsa");
    fs::write(&key_path, b"PRIVATE_KEY_DATA").unwrap();
    harness
        .cmd()
        .args([
            "set",
            "SSH_KEY",
            "--file",
            key_path.to_str().unwrap(),
            "--env-var",
            "SSH_KEY_PATH",
        ])
        .assert()
        .success();

    // Default load (all keys): exports text variables, does not export file secret
    let load_all = harness.cmd().arg("load").assert().success();
    let load_all_stdout = String::from_utf8_lossy(&load_all.get_output().stdout);
    assert!(load_all_stdout.contains("APP_ENV"));
    assert!(!load_all_stdout.contains("SSH_KEY"));

    // Explicit load with file secret name: prints warning on stderr
    harness
        .cmd()
        .args(["load", "SSH_KEY"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: Skipping file secret 'SSH_KEY' ($SSH_KEY_PATH)",
        ));
}

#[test]
fn test_file_secret_validation_rules() {
    let harness = FileTestHarness::new();

    let dummy_path = harness.local_dir.join("dummy.txt");
    fs::write(&dummy_path, b"dummy").unwrap();

    // 1. Invalid key name (contains slash or special chars not allowed in file identifier)
    harness
        .cmd()
        .args([
            "set",
            "bad/key",
            "--file",
            dummy_path.to_str().unwrap(),
            "--env-var",
            "VALID_ENV",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid file identifier: 'bad/key'",
        ));

    // 1b. Valid file identifier with dots and hyphens succeeds with valid --env-var
    harness
        .cmd()
        .args([
            "set",
            "ca.cert-2026.pem",
            "--file",
            dummy_path.to_str().unwrap(),
            "--env-var",
            "CA_CERT_PATH",
        ])
        .assert()
        .success();

    // 2. Invalid env_var name
    harness
        .cmd()
        .args([
            "set",
            "VALID_KEY",
            "--file",
            dummy_path.to_str().unwrap(),
            "--env-var",
            "123_INVALID",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid environment variable name",
        ));

    // 3. Oversized file exceeds 10 MB limit
    let large_file_path = harness.local_dir.join("large.dat");
    let mut f = File::create(&large_file_path).unwrap();
    let chunk = vec![0u8; 1024 * 1024]; // 1 MB
    for _ in 0..11 {
        f.write_all(&chunk).unwrap(); // 11 MB > 10 MB limit
    }
    drop(f);

    harness
        .cmd()
        .args([
            "set",
            "OVERSIZED",
            "--file",
            large_file_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "File exceeds the maximum supported size of 10 MB",
        ));
}

#[test]
fn test_file_secret_type_collision_guards() {
    let harness = FileTestHarness::new();

    let dummy_path = harness.local_dir.join("item.txt");
    fs::write(&dummy_path, b"sample text").unwrap();

    // 1. Set text secret
    harness
        .cmd()
        .args(["set", "CONFIG_ITEM"])
        .write_stdin("string_value")
        .assert()
        .success();

    // 2. Setting file secret with same key name must be rejected
    harness
        .cmd()
        .args(["set", "CONFIG_ITEM", "--file", dummy_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("currently a text secret"));

    // 3. Remove text secret and set as file secret
    harness
        .cmd()
        .args(["remove", "CONFIG_ITEM"])
        .assert()
        .success();

    harness
        .cmd()
        .args(["set", "CONFIG_ITEM", "--file", dummy_path.to_str().unwrap()])
        .assert()
        .success();

    // 4. Setting text secret with same key name must now be rejected
    harness
        .cmd()
        .args(["set", "CONFIG_ITEM"])
        .write_stdin("new_string_value")
        .assert()
        .failure()
        .stderr(predicate::str::contains("currently a file secret"));
}

#[test]
fn test_file_secret_token_granular_access() {
    let harness = FileTestHarness::new();

    let cert_data = b"SECRET CERTIFICATE PAYLOAD 12345";
    let cert_path = harness.local_dir.join("cert.bin");
    fs::write(&cert_path, cert_data).unwrap();

    harness
        .cmd()
        .args([
            "set",
            "CERT",
            "--file",
            cert_path.to_str().unwrap(),
            "--env-var",
            "CERT_FILE",
        ])
        .assert()
        .success();

    harness
        .cmd()
        .args(["set", "SECRET_KEY"])
        .write_stdin("secret_key_val")
        .assert()
        .success();

    // Create a token granting access only to CERT using CLI
    let token_file = harness.local_dir.join("cert.token");
    harness
        .cmd()
        .args(["token", "-o", token_file.to_str().unwrap(), "CERT"])
        .assert()
        .success();

    // Extract file using token
    let token_extracted = harness.local_dir.join("token_extracted.bin");
    harness
        .cmd()
        .args([
            "get",
            "CERT",
            "--token",
            token_file.to_str().unwrap(),
            "-o",
            token_extracted.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&token_extracted).unwrap(), cert_data);

    // Token lacking permission for SECRET_KEY should fail
    harness
        .cmd()
        .args(["get", "SECRET_KEY", "--token", token_file.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn test_file_secret_zstd_compression_roundtrip() {
    let harness = FileTestHarness::new();

    // Highly compressible payload: 50 KB of repeating data
    let compressible = "REPEAT_CHUNK_0123456789_".repeat(2000).into_bytes();
    let comp_path = harness.local_dir.join("compressible.txt");
    fs::write(&comp_path, &compressible).unwrap();

    harness
        .cmd()
        .args([
            "set",
            "COMPRESSED_FILE",
            "--file",
            comp_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let extracted_comp = harness.local_dir.join("extracted_comp.txt");
    harness
        .cmd()
        .args([
            "get",
            "COMPRESSED_FILE",
            "-o",
            extracted_comp.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&extracted_comp).unwrap(), compressible);

    // Incompressible payload: pseudo-random bytes
    let mut incompressible = vec![0u8; 4096];
    for (i, b) in incompressible.iter_mut().enumerate() {
        *b = ((i * 104729 + 17) % 256) as u8;
    }
    let incomp_path = harness.local_dir.join("incompressible.bin");
    fs::write(&incomp_path, &incompressible).unwrap();

    harness
        .cmd()
        .args([
            "set",
            "INCOMPRESSED_FILE",
            "--file",
            incomp_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let extracted_incomp = harness.local_dir.join("extracted_incomp.bin");
    harness
        .cmd()
        .args([
            "get",
            "INCOMPRESSED_FILE",
            "-o",
            extracted_incomp.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&extracted_incomp).unwrap(), incompressible);
}

#[test]
fn test_tag_inheritance_decrypt_success() {
    // Tests that secrets defined in BASE correctly decrypt and resolve
    // when queried under a scoped tag (such as --tag staging).
    let harness = FileTestHarness::new();

    // 1. Set variable in BASE
    harness
        .cmd()
        .args(["set", "INHERITED_BASE_SECRET"])
        .write_stdin("base_value_123")
        .assert()
        .success();

    // 2. Set tag-specific variable in STAGING
    harness
        .cmd()
        .args(["set", "--tag", "staging", "STAGING_ONLY_SECRET"])
        .write_stdin("staging_value_456")
        .assert()
        .success();

    // 3. Querying the inherited base secret under --tag staging succeeds
    harness
        .cmd()
        .args(["get", "--tag", "staging", "INHERITED_BASE_SECRET"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "INHERITED_BASE_SECRET: base_value_123",
        ));
}

#[test]
fn test_file_secret_edit_collision_prevention() {
    let harness = FileTestHarness::new();

    let cert_data = b"MOCK_CERT";
    let cert_file = harness.local_dir.join("cert.pem");
    fs::write(&cert_file, cert_data).unwrap();

    harness
        .cmd()
        .args([
            "set",
            "CERT_KEY",
            "--file",
            cert_file.to_str().unwrap(),
            "--env-var",
            "CERT_PATH",
        ])
        .assert()
        .success();

    // 1. Editor script tries to add a text secret named 'CERT_KEY' (collision with file secret id)
    let editor1 = harness.local_dir.join("editor1.sh");
    fs::write(
        &editor1,
        "#!/bin/sh\necho \"CERT_KEY=colliding_text\" >> \"$1\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&editor1, fs::Permissions::from_mode(0o755));
    }

    harness
        .cmd()
        .env("EDITOR", editor1.to_str().unwrap())
        .arg("edit")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "matches an existing file secret identifier",
        ));

    // 2. Editor script tries to add a text secret named 'CERT_PATH' (collision with target env var)
    let editor2 = harness.local_dir.join("editor2.sh");
    fs::write(
        &editor2,
        "#!/bin/sh\necho \"CERT_PATH=colliding_text\" >> \"$1\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&editor2, fs::Permissions::from_mode(0o755));
    }

    harness
        .cmd()
        .env("EDITOR", editor2.to_str().unwrap())
        .arg("edit")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "is already the target env variable ($CERT_PATH) for file secret 'CERT_KEY'",
        ));
}

#[test]
fn test_file_secret_merge_3way() {
    let harness = FileTestHarness::new();

    // Workaround for `cmd_merge` bug (which hardcodes allow_env=false in sudo_unlock):
    // Write identity into candidate identity files searched by envelope::discover_default_identities
    let ssh_dir = harness.config_dir.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    fs::write(
        ssh_dir.join("id_ed25519"),
        format!("{}\n", harness.identity_sec),
    )
    .unwrap();

    let app_support = harness
        .config_dir
        .join("Library/Application Support/dev.envseal.envseal");
    fs::create_dir_all(&app_support).unwrap();
    fs::write(
        app_support.join("identity.txt"),
        format!("{}\n", harness.identity_sec),
    )
    .unwrap();

    let base_path = harness.local_dir.join("base.envseal");
    let ours_path = harness.local_dir.join("ours.envseal");
    let theirs_path = harness.local_dir.join("theirs.envseal");

    // Common base vault
    harness
        .cmd()
        .args(["set", "BASE_TEXT"])
        .write_stdin("initial_base")
        .assert()
        .success();

    let base_bytes = fs::read(harness.local_dir.join(".envseal")).unwrap();
    fs::write(&base_path, &base_bytes).unwrap();

    // Ours adds a text variable
    harness
        .cmd()
        .args(["set", "OURS_VAR"])
        .write_stdin("ours_val")
        .assert()
        .success();
    let ours_bytes = fs::read(harness.local_dir.join(".envseal")).unwrap();
    fs::write(&ours_path, &ours_bytes).unwrap();

    // Reset harness vault back to base and add a file secret for theirs
    fs::write(harness.local_dir.join(".envseal"), &base_bytes).unwrap();
    let file_to_merge = harness.local_dir.join("theirs_cert.pem");
    fs::write(&file_to_merge, b"THEIRS_CERT_CONTENT").unwrap();
    harness
        .cmd()
        .args([
            "set",
            "THEIRS_FILE",
            "--file",
            file_to_merge.to_str().unwrap(),
            "--env-var",
            "THEIRS_CERT_PATH",
        ])
        .assert()
        .success();
    let theirs_bytes = fs::read(harness.local_dir.join(".envseal")).unwrap();
    fs::write(&theirs_path, &theirs_bytes).unwrap();

    // Merge theirs into ours
    harness
        .cmd()
        .args([
            "merge",
            "--base",
            base_path.to_str().unwrap(),
            "--ours",
            ours_path.to_str().unwrap(),
            "--theirs",
            theirs_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Successfully merged and resealed vault",
        ));

    // Verify ours now has both OURS_VAR and THEIRS_FILE
    fs::copy(&ours_path, harness.local_dir.join(".envseal")).unwrap();

    harness
        .cmd()
        .args(["get", "OURS_VAR"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OURS_VAR: ours_val"));

    let extracted_theirs = harness.local_dir.join("extracted_theirs.pem");
    harness
        .cmd()
        .args([
            "get",
            "THEIRS_FILE",
            "-o",
            extracted_theirs.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&extracted_theirs).unwrap(), b"THEIRS_CERT_CONTENT");
}

#[test]
fn test_file_secret_preserves_extension_and_executable_permissions() {
    let harness = FileTestHarness::new();

    // 1. JSON credential file
    let json_file = harness.local_dir.join("credentials.json");
    fs::write(&json_file, b"{\"client_id\": \"test-id\"}").unwrap();
    harness
        .cmd()
        .args([
            "set",
            "GCP_CREDS",
            "--file",
            json_file.to_str().unwrap(),
            "--env-var",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ])
        .assert()
        .success();

    // 2. Executable helper script
    let script_file = harness.local_dir.join("helper.sh");
    fs::write(&script_file, b"#!/bin/sh\necho helper-output\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script_file, fs::Permissions::from_mode(0o755)).unwrap();
    }
    harness
        .cmd()
        .args([
            "set",
            "HELPER_SCRIPT",
            "--file",
            script_file.to_str().unwrap(),
            "--env-var",
            "AUTH_HELPER",
        ])
        .assert()
        .success();

    // 3. Run and verify injected paths preserve extensions
    let runner_script = r#"
        echo "GCP_PATH=$GOOGLE_APPLICATION_CREDENTIALS"
        echo "HELPER_PATH=$AUTH_HELPER"
        "$AUTH_HELPER"
    "#;

    let run_output = harness
        .cmd()
        .args(["run", "--", "sh", "-c", runner_script])
        .assert()
        .success()
        .stdout(predicate::str::contains("helper-output"));

    let stdout = String::from_utf8_lossy(&run_output.get_output().stdout);
    for line in stdout.lines() {
        if let Some(p) = line.strip_prefix("GCP_PATH=") {
            assert!(
                p.ends_with(".json"),
                "Expected .json extension on injected GCP path, got: {p}"
            );
        }
        if let Some(p) = line.strip_prefix("HELPER_PATH=") {
            assert!(
                p.ends_with(".sh"),
                "Expected .sh extension on injected helper path, got: {p}"
            );
        }
    }

    // 4. Extract script via get -o and verify permissions
    let extracted_script = harness.local_dir.join("extracted_helper.sh");
    harness
        .cmd()
        .args([
            "get",
            "HELPER_SCRIPT",
            "-o",
            extracted_script.to_str().unwrap(),
        ])
        .assert()
        .success();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&extracted_script)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "Expected executable permission 0700 on extracted script"
        );
    }
}

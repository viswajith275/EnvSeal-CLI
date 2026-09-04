#[cfg(test)]
mod vault_integration_tests {
    use envseal::utils::crypto;
    use envseal::utils::is_valid_env_key;
    use envseal::utils::resolve::resolve_secrets;
    use envseal::utils::token::TokenManager;
    use envseal::utils::vault::{Entry, Vault, BASE_TAG};
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::{tempdir, TempDir};
    use zeroize::Zeroizing;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    struct TestEnv {
        _guard: MutexGuard<'static, ()>,
        _temp_dir: TempDir,
        pub vault_path: PathBuf,
    }

    impl TestEnv {
        fn new(filename: &str) -> Self {
            let guard = ENV_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let temp_dir = tempdir().expect("Failed to create isolated tempdir");
            let vault_path = temp_dir.path().join(filename);
            env::set_var("ENVSEAL_TEST_PATH", vault_path.to_str().unwrap());

            Self {
                _guard: guard,
                _temp_dir: temp_dir,
                vault_path,
            }
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            env::remove_var("ENVSEAL_TEST_PATH");
            env::remove_var("ENVSEAL_PASSWORD");
            env::remove_var("ENVSEAL_TAG_PASSWORD");
            env::remove_var("ENVSEAL_TOKEN");
        }
    }

    #[test]
    fn test_vault_initialization_and_overwrite_protection() {
        let _env = TestEnv::new(".envseal");

        let init_result = Vault::init("master_pass", true, false, None);
        assert!(init_result.is_ok(), "Vault should initialize successfully");

        let overwrite_result = Vault::init("master_pass", true, false, None);
        assert!(
            overwrite_result.is_err(),
            "Vault must refuse to overwrite an existing seal"
        );
        assert!(overwrite_result
            .unwrap_err()
            .to_string()
            .contains("already exists"));
    }

    #[test]
    fn test_signature_tamper_detection() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "API_KEY", "secret-123", None)
            .unwrap();

        vault.entries.get_mut("project").unwrap().base.insert(
            "INJECTED_KEY".to_string(),
            Entry {
                nonce: vec![0u8; 12],
                ciphertext: vec![0u8; 16],
            },
        );
        vault.save().unwrap();

        let tampered_vault = Vault::load(false, None).unwrap();
        let unlock_result = tampered_vault.unlock("master_pass");

        assert!(unlock_result.is_err());
        let err_msg = unlock_result.unwrap_err().to_string();
        assert!(
            err_msg.contains("signature verification failed") || err_msg.contains("SEAL TAMPERED"),
            "Expected tamper error, got: {err_msg}"
        );
    }

    #[test]
    fn test_raw_disk_corruption_detection() {
        let env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();

        let mut raw_bytes = fs::read(&env.vault_path).unwrap();
        let len = raw_bytes.len();
        raw_bytes[len - 5] ^= 0xFF;
        fs::write(&env.vault_path, raw_bytes).unwrap();

        let vault_res = Vault::load_from_file(&env.vault_path);
        if let Ok(vault) = vault_res {
            assert!(
                vault.verify_integrity().is_err(),
                "Vault with corrupted payload bytes must fail verification"
            );
        }
        // If vault_res is Err, rmp_serde successfully rejected the corrupted bytes
    }

    #[test]
    fn test_base_and_protected_tag_workflow() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "API_KEY", "secret-123", None)
            .unwrap();
        let retrieved = vault
            .get_entry(&keys.master_dek, None, None, "API_KEY", None)
            .unwrap();
        assert_eq!(retrieved.as_str(), "secret-123");

        vault
            .create_protected_tag(&keys.signing_key, None, "prod", "tag_pass")
            .unwrap();
        assert!(vault.is_tag_protected(None, Some("prod")).unwrap());

        let create_base_err = vault.create_protected_tag(&keys.signing_key, None, "base", "pass");
        assert!(create_base_err.is_err());
        assert!(create_base_err.unwrap_err().to_string().contains("base"));

        let dup_err = vault.create_protected_tag(&keys.signing_key, None, "prod", "tag_pass");
        assert!(dup_err.is_err());
        assert!(dup_err.unwrap_err().to_string().contains("already exists"));

        let tag_key = vault.unlock_tag(None, "prod", "tag_pass").unwrap();
        vault
            .set_entry(
                &keys,
                None,
                Some("prod"),
                "DB_PASS",
                "prod-db-123",
                Some(&tag_key),
            )
            .unwrap();

        let retrieved_tag = vault
            .get_entry(
                &keys.master_dek,
                None,
                Some("prod"),
                "DB_PASS",
                Some(&tag_key),
            )
            .unwrap();
        assert_eq!(retrieved_tag.as_str(), "prod-db-123");

        // Verify base key inheritance fallback works when querying tag
        let inherited_val = vault
            .get_entry(
                &keys.master_dek,
                None,
                Some("prod"),
                "API_KEY",
                Some(&tag_key),
            )
            .unwrap();
        assert_eq!(inherited_val.as_str(), "secret-123");
    }

    #[test]
    fn test_tag_overrides_base_variable_precedence() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "PORT", "3000", None)
            .unwrap();

        vault
            .create_protected_tag(&keys.signing_key, None, "prod", "prod_pass")
            .unwrap();
        let tag_key = vault.unlock_tag(None, "prod", "prod_pass").unwrap();

        vault
            .set_entry(&keys, None, Some("prod"), "PORT", "8080", Some(&tag_key))
            .unwrap();

        let base_val = vault
            .get_entry(&keys.master_dek, None, None, "PORT", None)
            .unwrap();
        assert_eq!(base_val.as_str(), "3000");

        let prod_val = vault
            .get_entry(&keys.master_dek, None, Some("prod"), "PORT", Some(&tag_key))
            .unwrap();
        assert_eq!(prod_val.as_str(), "8080");
    }

    #[test]
    fn test_entry_removal_edge_cases() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "KEY1", "val1", None)
            .unwrap();

        let remove_base_err = vault.remove_entry(&keys.signing_key, None, Some("base"), None, None);
        assert!(remove_base_err.is_err());
        assert!(remove_base_err
            .unwrap_err()
            .to_string()
            .contains("Cannot remove"));

        vault
            .remove_entry(&keys.signing_key, None, None, Some("KEY1"), None)
            .unwrap();
        let get_err = vault.get_entry(&keys.master_dek, None, None, "KEY1", None);
        assert!(get_err.is_err());
    }

    #[test]
    fn test_local_vault_group_isolation() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();

        let resolve_err = vault.resolve_group_name(Some("CUSTOM_GROUP"));
        assert!(resolve_err.is_err());
        assert!(resolve_err
            .unwrap_err()
            .to_string()
            .contains("do not support multiple groups"));

        let keys = vault.unlock("master_pass").unwrap();
        let link_err = vault.link_group(&keys.signing_key, "NEW_GROUP");
        assert!(link_err.is_err());
        assert!(link_err
            .unwrap_err()
            .to_string()
            .contains("cannot configure linking"));
    }

    #[test]
    fn test_failed_authentication_attempts() {
        let _env = TestEnv::new(".envseal");

        Vault::init("correct_master", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();

        let bad_master_err = vault.unlock("wrong_master");
        assert!(bad_master_err.is_err());

        let keys = vault.unlock("correct_master").unwrap();
        vault
            .create_protected_tag(&keys.signing_key, None, "staging", "correct_tag_pass")
            .unwrap();

        let bad_tag_err = vault.unlock_tag(None, "staging", "wrong_tag_pass");
        assert!(bad_tag_err.is_err());
        assert!(bad_tag_err
            .unwrap_err()
            .to_string()
            .contains("Wrong tag password"));
    }

    #[test]
    fn test_master_password_change_preserves_entries() {
        let _env = TestEnv::new(".envseal");

        Vault::init("initial_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("initial_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "STATIC_KEY", "important_secret", None)
            .unwrap();

        vault
            .change_master_password(&keys, "new_secure_pass")
            .unwrap();

        let reloaded = Vault::load(false, None).unwrap();
        assert!(reloaded.unlock("initial_pass").is_err());

        let new_keys = reloaded.unlock("new_secure_pass").unwrap();
        let val = reloaded
            .get_entry(&new_keys.master_dek, None, None, "STATIC_KEY", None)
            .unwrap();
        assert_eq!(val.as_str(), "important_secret");
    }

    #[test]
    fn test_custom_profile_naming() {
        let env = TestEnv::new(".prod.envseal");

        Vault::init("master_pass", true, false, Some("prod")).unwrap();
        assert!(env.vault_path.exists());

        let vault = Vault::load(false, Some("prod")).unwrap();
        assert!(vault.is_local());
    }

    #[test]
    fn test_list_all_keys() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "BASE_KEY_1", "v1", None)
            .unwrap();
        vault
            .set_entry(&keys, None, None, "BASE_KEY_2", "v2", None)
            .unwrap();

        vault
            .create_protected_tag(&keys.signing_key, None, "dev", "tag_pass")
            .unwrap();
        let tag_key = vault.unlock_tag(None, "dev", "tag_pass").unwrap();
        vault
            .set_entry(&keys, None, Some("dev"), "DEV_KEY_1", "v3", Some(&tag_key))
            .unwrap();

        let base_keys = vault.list_all_keys(None, None).unwrap();
        assert_eq!(base_keys.len(), 2);
        assert!(base_keys.contains(&"BASE_KEY_1".to_string()));

        let dev_keys = vault.list_all_keys(None, Some("dev")).unwrap();
        assert_eq!(dev_keys.len(), 3);
        assert!(dev_keys.contains(&"DEV_KEY_1".to_string()));
        assert!(dev_keys.contains(&"BASE_KEY_1".to_string()));
    }

    #[test]
    fn test_regression_resolve_secrets_infers_tag_and_overrides_without_cli_flag() {
        let env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        // 1. Configure base entries
        vault
            .set_entry(&keys, None, None, "SHARED_HOST", "base.internal", None)
            .unwrap();
        vault
            .set_entry(&keys, None, None, "PORT", "3000", None)
            .unwrap();

        // 2. Configure protected tag with an override (PORT) and an exclusive key (PROD_SECRET)
        vault
            .create_protected_tag(&keys.signing_key, None, "prod", "tag_pass")
            .unwrap();
        let tag_key = vault.unlock_tag(None, "prod", "tag_pass").unwrap();

        vault
            .set_entry(&keys, None, Some("prod"), "PORT", "8080", Some(&tag_key))
            .unwrap();
        vault
            .set_entry(
                &keys,
                None,
                Some("prod"),
                "PROD_SECRET",
                "super-secure-token",
                Some(&tag_key),
            )
            .unwrap();

        // 3. Mint token scoped to "prod" (inherits base, overrides PORT)
        let token_string = vault
            .create_token(
                &keys.signing_key,
                &keys.master_dek,
                None,
                Some("prod"),
                Some(&tag_key),
                "ci-worker",
                Some(1800),
                Some("Automated regression test token"),
                None,
            )
            .unwrap();

        let token_file_path = env.vault_path.parent().unwrap().join("scoped.token");
        fs::write(&token_file_path, &token_string).unwrap();

        // 4. Resolve secrets passing `None` as the tag parameter
        let resolved = resolve_secrets(
            &vault,
            None,
            None, // Inferred automatically from token scope
            Some(&token_file_path),
            false,
        )
        .expect("resolve_secrets must infer tag from token payload when CLI tag is None");

        // 5. Validate inheritance, overrides, and tag-only entries
        assert_eq!(
            resolved.get("SHARED_HOST").map(|s| s.as_str()),
            Some("base.internal"),
            "Unmodified base secret should be present"
        );
        assert_eq!(
            resolved.get("PORT").map(|s| s.as_str()),
            Some("8080"),
            "Tag override must take precedence over the base secret value"
        );
        assert_eq!(
            resolved.get("PROD_SECRET").map(|s| s.as_str()),
            Some("super-secure-token"),
            "Tag-specific secret must be decrypted"
        );
        assert_eq!(resolved.len(), 3);
    }

    #[test]
    fn test_protected_tag_deletion_rules() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .create_protected_tag(&keys.signing_key, None, "secure_tag", "tag_pass")
            .unwrap();

        let unauth_remove_err =
            vault.remove_entry(&keys.signing_key, None, Some("secure_tag"), None, None);
        assert!(unauth_remove_err.is_err());
        assert!(unauth_remove_err
            .unwrap_err()
            .to_string()
            .contains("Password required"));

        let tag_key = vault.unlock_tag(None, "secure_tag", "tag_pass").unwrap();
        vault
            .remove_entry(
                &keys.signing_key,
                None,
                Some("secure_tag"),
                None,
                Some(&tag_key),
            )
            .unwrap();

        assert!(!vault.is_tag_protected(None, Some("secure_tag")).unwrap());
    }

    #[test]
    fn test_rotate_base_scope_dek() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "API_KEY", "secret-123", None)
            .unwrap();

        vault
            .rotate_scope_dek(&keys, None, None, None, None)
            .unwrap();

        let rotated_keys = vault.unlock("master_pass").unwrap();
        let retrieved = vault
            .get_entry(&rotated_keys.master_dek, None, None, "API_KEY", None)
            .unwrap();
        assert_eq!(retrieved.as_str(), "secret-123");
    }

    #[test]
    fn test_rotate_protected_tag_dek_with_entries() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .create_protected_tag(&keys.signing_key, None, "prod", "tag_pass")
            .unwrap();
        let tag_key = vault.unlock_tag(None, "prod", "tag_pass").unwrap();

        vault
            .set_entry(
                &keys,
                None,
                Some("prod"),
                "DB_PASS",
                "prod-db-123",
                Some(&tag_key),
            )
            .unwrap();

        let rotate_no_dek =
            vault.rotate_scope_dek(&keys, None, Some("prod"), None, Some("tag_pass"));
        assert!(rotate_no_dek.is_err());
        assert!(rotate_no_dek
            .unwrap_err()
            .to_string()
            .contains("Password required for protected tag"));

        let rotate_no_pass =
            vault.rotate_scope_dek(&keys, None, Some("prod"), Some(&tag_key), None);
        assert!(rotate_no_pass.is_err());
        assert!(rotate_no_pass
            .unwrap_err()
            .to_string()
            .contains("Tag password required"));

        vault
            .rotate_scope_dek(&keys, None, Some("prod"), Some(&tag_key), Some("tag_pass"))
            .unwrap();

        let new_tag_key = vault.unlock_tag(None, "prod", "tag_pass").unwrap();
        let retrieved = vault
            .get_entry(
                &keys.master_dek,
                None,
                Some("prod"),
                "DB_PASS",
                Some(&new_tag_key),
            )
            .unwrap();
        assert_eq!(retrieved.as_str(), "prod-db-123");
    }

    #[test]
    fn test_zero_trust_token_generation_and_granular_access() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "GRANTED_KEY", "access-granted", None)
            .unwrap();
        vault
            .set_entry(&keys, None, None, "DENIED_KEY", "access-denied", None)
            .unwrap();

        let base_scope_dek = crypto::derive_scope_dek(&keys.master_dek, "project", BASE_TAG);
        let entry_key = crypto::derive_entry_key(&base_scope_dek, "GRANTED_KEY");

        let mut token_keys = HashMap::new();
        token_keys.insert(
            "GRANTED_KEY".to_string(),
            Zeroizing::new(entry_key.to_vec()),
        );

        let scope_str = vault.tag_scope(None, BASE_TAG).unwrap();
        let token_string = TokenManager::create(
            &keys.signing_key,
            &scope_str,
            token_keys,
            "ci-agent",
            Some(3600),
            Some("Integration test execution"),
        )
        .unwrap();

        let payload = TokenManager::verify_and_extract(&token_string, &vault.public_key).unwrap();
        let decrypted = vault.decrypt_from_token(None, None, &payload).unwrap();

        assert_eq!(decrypted.len(), 1);
        assert_eq!(
            decrypted.get("GRANTED_KEY").unwrap().as_str(),
            "access-granted"
        );
        assert!(!decrypted.contains_key("DENIED_KEY"));
    }

    #[test]
    fn test_token_tampering_and_expiration_rejections() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        let base_scope_dek = crypto::derive_scope_dek(&keys.master_dek, "project", BASE_TAG);
        let entry_key = crypto::derive_entry_key(&base_scope_dek, "API");
        let mut token_keys = HashMap::new();
        token_keys.insert("API".to_string(), Zeroizing::new(entry_key.to_vec()));

        let scope_str = vault.tag_scope(None, BASE_TAG).unwrap();

        let expired_token = TokenManager::create(
            &keys.signing_key,
            &scope_str,
            token_keys.clone(),
            "ci",
            Some(0),
            None,
        )
        .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1100));
        let Err(err) = TokenManager::verify_and_extract(&expired_token, &vault.public_key) else {
            panic!("Expected token verification to fail, but it succeeded");
        };
        assert!(err.to_string().contains("Token expired"));

        let valid_token = TokenManager::create(
            &keys.signing_key,
            &scope_str,
            token_keys,
            "ci",
            Some(600),
            None,
        )
        .unwrap();

        let mut tampered_token = valid_token.clone();
        tampered_token.push_str("tamper");
        assert!(TokenManager::verify_and_extract(&tampered_token, &vault.public_key).is_err());
    }

    #[test]
    fn test_dek_rotation_invalidates_active_tokens() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "ROTATE_KEY", "sensitive-val", None)
            .unwrap();

        let base_scope_dek = crypto::derive_scope_dek(&keys.master_dek, "project", BASE_TAG);
        let entry_key = crypto::derive_entry_key(&base_scope_dek, "ROTATE_KEY");
        let mut token_keys = HashMap::new();
        token_keys.insert("ROTATE_KEY".to_string(), Zeroizing::new(entry_key.to_vec()));

        let scope_str = vault.tag_scope(None, BASE_TAG).unwrap();
        let token = TokenManager::create(
            &keys.signing_key,
            &scope_str,
            token_keys,
            "agent",
            Some(3600),
            None,
        )
        .unwrap();

        let payload = TokenManager::verify_and_extract(&token, &vault.public_key).unwrap();
        assert!(vault.decrypt_from_token(None, None, &payload).is_ok());

        vault
            .rotate_scope_dek(&keys, None, None, None, None)
            .unwrap();

        let decryption_attempt = vault.decrypt_from_token(None, None, &payload);
        assert!(decryption_attempt.is_err());
        assert!(decryption_attempt
            .unwrap_err()
            .to_string()
            .contains("revoked"));
    }

    #[test]
    fn test_resolve_secrets_via_token_file() {
        let env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "CONFIG_ENV", "production", None)
            .unwrap();

        let base_scope_dek = crypto::derive_scope_dek(&keys.master_dek, "project", BASE_TAG);
        let entry_key = crypto::derive_entry_key(&base_scope_dek, "CONFIG_ENV");
        let mut token_keys = HashMap::new();
        token_keys.insert("CONFIG_ENV".to_string(), Zeroizing::new(entry_key.to_vec()));

        let scope_str = vault.tag_scope(None, BASE_TAG).unwrap();
        let token_string = TokenManager::create(
            &keys.signing_key,
            &scope_str,
            token_keys,
            "ci-pipeline",
            Some(600),
            None,
        )
        .unwrap();

        let token_file_path = env.vault_path.parent().unwrap().join("test.token");
        fs::write(&token_file_path, token_string).unwrap();

        let resolved = resolve_secrets(&vault, None, None, Some(&token_file_path), false).unwrap();
        assert_eq!(resolved.get("CONFIG_ENV").unwrap().as_str(), "production");
    }

    #[test]
    fn test_protected_tag_blocks_unauthorized_group_deletion() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        // Create a protected tag within the local default 'project' group
        vault
            .create_protected_tag(&keys.signing_key, None, "prod", "tag_pass")
            .unwrap();
        let tag_key = vault.unlock_tag(None, "prod", "tag_pass").unwrap();

        // Attempting to wipe the entire group without a tag key must fail
        let delete_group_err = vault.remove_entry(&keys.signing_key, None, None, None, None);
        assert!(delete_group_err.is_err());
        assert!(delete_group_err
            .unwrap_err()
            .to_string()
            .contains("contains protected tags"));

        // Providing the authorized tag key allows deleting the group
        let delete_group_ok =
            vault.remove_entry(&keys.signing_key, None, None, None, Some(&tag_key));
        assert!(delete_group_ok.is_ok());
        assert!(!vault.entries.contains_key("project"));
    }

    #[test]
    fn test_token_scope_mismatch_rejection() {
        let env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "SECRET", "val", None)
            .unwrap();

        let base_scope_dek = crypto::derive_scope_dek(&keys.master_dek, "project", BASE_TAG);
        let entry_key = crypto::derive_entry_key(&base_scope_dek, "SECRET");

        let mut token_keys = HashMap::new();
        token_keys.insert("SECRET".to_string(), Zeroizing::new(entry_key.to_vec()));

        // Mint token scoped explicitly to BASE_TAG
        let scope_str = vault.tag_scope(None, BASE_TAG).unwrap();
        let token_string = TokenManager::create(
            &keys.signing_key,
            &scope_str,
            token_keys,
            "ci-agent",
            Some(3600),
            None,
        )
        .unwrap();

        let token_file_path = env.vault_path.parent().unwrap().join("scope.token");
        fs::write(&token_file_path, token_string).unwrap();

        // Attempt to resolve secrets for a different tag scope ('staging')
        let resolve_err =
            resolve_secrets(&vault, None, Some("staging"), Some(&token_file_path), false);
        assert!(resolve_err.is_err());
        assert!(resolve_err
            .unwrap_err()
            .to_string()
            .contains("Token scope mismatch"));
    }

    #[test]
    fn test_partial_tag_inheritance_resolution() {
        let _env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        // Populate base group variables
        vault
            .set_entry(
                &keys,
                None,
                None,
                "COMMON_URL",
                "https://api.domain.com",
                None,
            )
            .unwrap();
        vault
            .set_entry(&keys, None, None, "TIMEOUT_SEC", "30", None)
            .unwrap();

        // Create an unprotected tag and only override TIMEOUT_SEC
        vault
            .set_entry(&keys, None, Some("staging"), "TIMEOUT_SEC", "120", None)
            .unwrap();

        // When queried under 'staging', COMMON_URL must inherit from base
        let inherited = vault
            .get_entry(&keys.master_dek, None, Some("staging"), "COMMON_URL", None)
            .unwrap();
        assert_eq!(inherited.as_str(), "https://api.domain.com");

        // TIMEOUT_SEC must return the tag-specific override
        let overridden = vault
            .get_entry(&keys.master_dek, None, Some("staging"), "TIMEOUT_SEC", None)
            .unwrap();
        assert_eq!(overridden.as_str(), "120");

        // Non-existent keys must fail across both scopes
        let non_existent =
            vault.get_entry(&keys.master_dek, None, Some("staging"), "NOT_FOUND", None);
        assert!(non_existent.is_err());
    }

    #[test]
    fn test_session_manager_lifecycle_and_clearing() {
        use envseal::utils::session::{CachedKeys, SessionManager};

        let test_scope = "test_memory_session_scope";
        let dummy_kek = [0x42u8; crypto::KEY_LEN];
        let dummy_seed = [0x24u8; crypto::KEY_LEN];

        SessionManager::cache_keys(
            test_scope,
            CachedKeys::Master {
                kek: dummy_kek,
                seed: dummy_seed,
            },
        )
        .unwrap();

        // Ensure key material can be retrieved
        let active = SessionManager::get_active_keys(test_scope)
            .unwrap()
            .expect("Session key should be present in cache");

        match active {
            CachedKeys::Master { kek, seed } => {
                assert_eq!(kek, dummy_kek);
                assert_eq!(seed, dummy_seed);
            }
            _ => panic!("Expected CachedKeys::Master"),
        }

        // Wipe session
        SessionManager::clear_session(test_scope).unwrap();
        let cleared = SessionManager::get_active_keys(test_scope).unwrap();
        assert!(cleared.is_none());
    }

    #[test]
    fn test_token_always_includes_base_and_overrides_with_tag() {
        let env = TestEnv::new(".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        // 1. Populate base values
        vault
            .set_entry(&keys, None, None, "COMMON_URL", "https://api.test", None)
            .unwrap();
        vault
            .set_entry(&keys, None, None, "PORT", "3000", None)
            .unwrap();

        // 2. Populate tag override and tag-specific value
        vault
            .create_protected_tag(&keys.signing_key, None, "prod", "tag_pass")
            .unwrap();
        let tag_key = vault.unlock_tag(None, "prod", "tag_pass").unwrap();

        vault
            .set_entry(&keys, None, Some("prod"), "PORT", "8080", Some(&tag_key))
            .unwrap();
        vault
            .set_entry(
                &keys,
                None,
                Some("prod"),
                "PROD_ONLY",
                "active",
                Some(&tag_key),
            )
            .unwrap();

        // 3. Generate token for tag "prod"
        let token_string = vault
            .create_token(
                &keys.signing_key,
                &keys.master_dek,
                None,
                Some("prod"),
                Some(&tag_key),
                "ci-deployer",
                Some(3600),
                Some("Deploy pipeline token"),
                None,
            )
            .unwrap();

        let token_file_path = env.vault_path.parent().unwrap().join("deploy.token");
        fs::write(&token_file_path, &token_string).unwrap();

        // 4. Resolve secrets without specifying --tag; tag is inferred from token
        let resolved = resolve_secrets(&vault, None, None, Some(&token_file_path), false).unwrap();

        // Base variable was included
        assert_eq!(
            resolved.get("COMMON_URL").unwrap().as_str(),
            "https://api.test"
        );
        // Base variable was overridden by tag value
        assert_eq!(resolved.get("PORT").unwrap().as_str(), "8080");
        // Tag-specific variable was included
        assert_eq!(resolved.get("PROD_ONLY").unwrap().as_str(), "active");
    }

    #[test]
    fn test_valid_env_key_syntax_validation() {
        assert!(is_valid_env_key("API_KEY"));
        assert!(is_valid_env_key("_SECRET"));
        assert!(is_valid_env_key("PORT_8080"));
        assert!(is_valid_env_key("v"));

        assert!(!is_valid_env_key("8080_PORT"));
        assert!(!is_valid_env_key("API-KEY"));
        assert!(!is_valid_env_key("ENV.KEY"));
        assert!(!is_valid_env_key("API KEY"));
        assert!(!is_valid_env_key(""));
    }
}

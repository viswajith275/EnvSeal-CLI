#[cfg(test)]
mod vault_integration_tests {
    use age::secrecy::ExposeSecret;
    use envseal::utils::crypto;
    use envseal::utils::envelope;
    use envseal::utils::is_valid_env_key;
    use envseal::utils::resolve;
    use envseal::utils::session::{CachedKeys, SessionManager};
    use envseal::utils::token::TokenManager;
    use envseal::utils::vault::{Entry, Group, Vault, BASE_TAG, LOCAL_GROUP_NAME};
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::{tempdir, TempDir};
    use zeroize::Zeroizing;

    // serializes env-var mutations across test threads with a static mutex; upgrade path: isolate test runs with separate processes
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    struct TestEnv {
        _guard: MutexGuard<'static, ()>,
        _temp_dir: TempDir,
        pub vault_path: PathBuf,
        pub recipient: String,
    }

    impl TestEnv {
        fn new(filename: &str) -> Self {
            let guard = ENV_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let temp_dir = tempdir().expect("Failed to create isolated tempdir");
            let vault_path = temp_dir.path().join(filename);

            let id = age::x25519::Identity::generate();
            let recipient = id.to_public().to_string();
            let identity_secret = id.to_string().expose_secret().to_string();

            env::set_var("ENVSEAL_TEST_PATH", vault_path.to_str().unwrap());
            env::set_var("ENVSEAL_IDENTITY", &identity_secret);

            Self {
                _guard: guard,
                _temp_dir: temp_dir,
                vault_path,
                recipient,
            }
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            env::remove_var("ENVSEAL_TEST_PATH");
            env::remove_var("ENVSEAL_IDENTITY");
            env::remove_var("ENVSEAL_TOKEN");
        }
    }

    #[test]
    fn test_vault_initialization_and_overwrite_protection() {
        let env = TestEnv::new(".envseal");
        let init_result = Vault::init(vec![env.recipient.clone()], true, false, None);
        assert!(init_result.is_ok(), "Vault should initialize successfully");
        let overwrite_result = Vault::init(vec![env.recipient.clone()], true, false, None);
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
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault
            .set_entry(&keys, None, None, "API_KEY", "secret-123")
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
        let unlock_result = tampered_vault.unlock(true);
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
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
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
    }

    #[test]
    fn test_base_and_tag_workflow() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();

        vault
            .set_entry(&keys, None, None, "API_KEY", "secret-123")
            .unwrap();
        let retrieved = vault
            .get_entry(&keys.master_dek, None, None, "API_KEY")
            .unwrap();
        assert_eq!(retrieved.as_str(), "secret-123");

        vault
            .set_entry(&keys, None, Some("prod"), "DB_PASS", "prod-db-123")
            .unwrap();
        let retrieved_tag = vault
            .get_entry(&keys.master_dek, None, Some("prod"), "DB_PASS")
            .unwrap();
        assert_eq!(retrieved_tag.as_str(), "prod-db-123");

        let inherited_val = vault
            .get_entry(&keys.master_dek, None, Some("prod"), "API_KEY")
            .unwrap();
        assert_eq!(inherited_val.as_str(), "secret-123");
    }

    #[test]
    fn test_tag_overrides_base_variable_precedence() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault.set_entry(&keys, None, None, "PORT", "3000").unwrap();
        vault
            .set_entry(&keys, None, Some("prod"), "PORT", "8080")
            .unwrap();
        let base_val = vault
            .get_entry(&keys.master_dek, None, None, "PORT")
            .unwrap();
        assert_eq!(base_val.as_str(), "3000");
        let prod_val = vault
            .get_entry(&keys.master_dek, None, Some("prod"), "PORT")
            .unwrap();
        assert_eq!(prod_val.as_str(), "8080");
    }

    #[test]
    fn test_entry_removal_edge_cases() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault.set_entry(&keys, None, None, "KEY1", "val1").unwrap();

        let remove_base_err = vault.remove_entry(&keys.signing_key, None, Some("base"), None);
        assert!(remove_base_err.is_err());
        assert!(remove_base_err
            .unwrap_err()
            .to_string()
            .contains("Cannot remove default 'base' tag"));

        vault
            .remove_entry(&keys.signing_key, None, None, Some("KEY1"))
            .unwrap();
        let get_err = vault.get_entry(&keys.master_dek, None, None, "KEY1");
        assert!(get_err.is_err());

        vault
            .set_entry(&keys, None, Some("dev"), "DEV_KEY", "val")
            .unwrap();
        vault
            .remove_entry(&keys.signing_key, None, Some("dev"), None)
            .unwrap();
        assert!(vault
            .get_entry(&keys.master_dek, None, Some("dev"), "DEV_KEY")
            .is_err());
    }

    #[test]
    fn test_local_vault_group_isolation() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let resolve_err = vault.resolve_group_name(Some("CUSTOM_GROUP"));
        assert!(resolve_err.is_err());
        assert!(resolve_err
            .unwrap_err()
            .to_string()
            .contains("do not support multiple groups"));

        let keys = vault.unlock(true).unwrap();
        let link_err = vault.link_group(&keys.signing_key, "NEW_GROUP");
        assert!(link_err.is_err());
        assert!(link_err
            .unwrap_err()
            .to_string()
            .contains("cannot configure linking"));
    }

    #[test]
    fn test_failed_authentication_attempts() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let vault = Vault::load(false, None).unwrap();

        let wrong_id = age::x25519::Identity::generate();
        env::set_var("ENVSEAL_IDENTITY", wrong_id.to_string().expose_secret());
        let bad_unlock = vault.unlock(true);
        assert!(bad_unlock.is_err());
        assert!(bad_unlock
            .unwrap_err()
            .to_string()
            .contains("Access Denied"));

        env::remove_var("ENVSEAL_IDENTITY");
        assert!(vault.unlock(false).is_err());
    }

    #[test]
    fn test_recipient_rotation_preserves_entries() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault
            .set_entry(&keys, None, None, "STATIC_KEY", "important_secret")
            .unwrap();

        let new_id = age::x25519::Identity::generate();
        let new_recip = new_id.to_public().to_string();
        vault.recipients = vec![new_recip];
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&*keys.master_dek);
        payload[32..].copy_from_slice(keys.signing_key.to_bytes().as_slice());
        vault.envelope = envelope::wrap_envelope(&payload, &vault.recipients).unwrap();
        vault.seal_integrity(&keys.signing_key).unwrap();
        vault.save().unwrap();

        let reloaded = Vault::load(false, None).unwrap();
        assert!(reloaded.unlock(true).is_err());

        env::set_var("ENVSEAL_IDENTITY", new_id.to_string().expose_secret());
        let new_keys = reloaded.unlock(true).unwrap();
        let val = reloaded
            .get_entry(&new_keys.master_dek, None, None, "STATIC_KEY")
            .unwrap();
        assert_eq!(val.as_str(), "important_secret");
    }

    #[test]
    fn test_custom_profile_naming() {
        let env = TestEnv::new(".prod.envseal");
        Vault::init(vec![env.recipient.clone()], true, false, Some("prod")).unwrap();
        assert!(env.vault_path.exists());
        let vault = Vault::load(false, Some("prod")).unwrap();
        assert!(vault.is_local());
    }

    #[test]
    fn test_list_all_keys() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault
            .set_entry(&keys, None, None, "BASE_KEY_1", "v1")
            .unwrap();
        vault
            .set_entry(&keys, None, None, "BASE_KEY_2", "v2")
            .unwrap();
        vault
            .set_entry(&keys, None, Some("dev"), "DEV_KEY_1", "v3")
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
    fn test_resolve_environment_with_token_and_tag_inheritance() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault
            .set_entry(&keys, None, None, "SHARED_HOST", "base.internal")
            .unwrap();
        vault.set_entry(&keys, None, None, "PORT", "3000").unwrap();
        vault
            .set_entry(&keys, None, Some("prod"), "PORT", "8080")
            .unwrap();
        vault
            .set_entry(
                &keys,
                None,
                Some("prod"),
                "PROD_SECRET",
                "super-secure-token",
            )
            .unwrap();

        let token_string = vault
            .create_token(
                &keys.signing_key,
                &keys.master_dek,
                None,
                Some("prod"),
                "ci-worker",
                Some(1800),
                Some("Automated regression test token"),
                None,
            )
            .unwrap();

        let token_file_path = env.vault_path.parent().unwrap().join("scoped.token");
        fs::write(&token_file_path, &token_string).unwrap();

        let loaded = resolve::load_token(Some(token_file_path.to_str().unwrap())).unwrap();
        let resolved =
            resolve::resolve_environment(&vault, None, Some("prod"), loaded.as_deref(), false)
                .unwrap();
        assert_eq!(
            resolved.get("SHARED_HOST").map(|s| s.as_str()),
            Some("base.internal")
        );
        assert_eq!(resolved.get("PORT").map(|s| s.as_str()), Some("8080"));
        assert_eq!(
            resolved.get("PROD_SECRET").map(|s| s.as_str()),
            Some("super-secure-token")
        );
        assert_eq!(resolved.len(), 3);
    }

    #[test]
    fn test_zero_trust_token_generation_and_granular_access() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault
            .set_entry(&keys, None, None, "GRANTED_KEY", "access-granted")
            .unwrap();
        vault
            .set_entry(&keys, None, None, "DENIED_KEY", "access-denied")
            .unwrap();

        let token_string = vault
            .create_token(
                &keys.signing_key,
                &keys.master_dek,
                None,
                None,
                "ci-agent",
                Some(3600),
                Some("Integration test execution"),
                Some(&["GRANTED_KEY".to_string()]),
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
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
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
        let err = TokenManager::verify_and_extract(&expired_token, &vault.public_key).unwrap_err();
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
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault
            .set_entry(&keys, None, None, "ROTATE_KEY", "sensitive-val")
            .unwrap();

        let token = vault
            .create_token(
                &keys.signing_key,
                &keys.master_dek,
                None,
                None,
                "agent",
                Some(3600),
                None,
                None,
            )
            .unwrap();
        let payload = TokenManager::verify_and_extract(&token, &vault.public_key).unwrap();
        assert!(vault.decrypt_from_token(None, None, &payload).is_ok());

        vault.rotate_dek(&keys).unwrap();
        let decryption_attempt = vault.decrypt_from_token(None, None, &payload);
        assert!(decryption_attempt.is_err());
        assert!(decryption_attempt
            .unwrap_err()
            .to_string()
            .contains("revoked"));
    }

    #[test]
    fn test_token_scope_mismatch_rejection() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault.set_entry(&keys, None, None, "SECRET", "val").unwrap();

        let token_string = vault
            .create_token(
                &keys.signing_key,
                &keys.master_dek,
                None,
                None,
                "ci-agent",
                Some(3600),
                None,
                None,
            )
            .unwrap();

        let resolve_err =
            resolve::resolve_environment(&vault, None, Some("staging"), Some(&token_string), false);
        assert!(resolve_err.is_err());
        assert!(resolve_err
            .unwrap_err()
            .to_string()
            .contains("Token scope mismatch"));
    }

    #[test]
    fn test_partial_tag_inheritance_resolution() {
        let env = TestEnv::new(".envseal");
        Vault::init(vec![env.recipient.clone()], true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock(true).unwrap();
        vault
            .set_entry(&keys, None, None, "COMMON_URL", "https://api.domain.com")
            .unwrap();
        vault
            .set_entry(&keys, None, None, "TIMEOUT_SEC", "30")
            .unwrap();
        vault
            .set_entry(&keys, None, Some("staging"), "TIMEOUT_SEC", "120")
            .unwrap();

        let inherited = vault
            .get_entry(&keys.master_dek, None, Some("staging"), "COMMON_URL")
            .unwrap();
        assert_eq!(inherited.as_str(), "https://api.domain.com");

        let overridden = vault
            .get_entry(&keys.master_dek, None, Some("staging"), "TIMEOUT_SEC")
            .unwrap();
        assert_eq!(overridden.as_str(), "120");

        let non_existent = vault.get_entry(&keys.master_dek, None, Some("staging"), "NOT_FOUND");
        assert!(non_existent.is_err());
    }

    #[test]
    fn test_session_manager_lifecycle_and_clearing() {
        let test_scope = "test_memory_session_scope";
        let dummy_dek = [0x42u8; crypto::KEY_LEN];
        let dummy_seed = [0x24u8; crypto::KEY_LEN];
        SessionManager::cache_keys(
            test_scope,
            CachedKeys::Master {
                dek: dummy_dek,
                seed: dummy_seed,
            },
        )
        .unwrap();

        if let Ok(Some(active)) = SessionManager::get_active_keys(test_scope) {
            match active {
                CachedKeys::Master { dek, seed } => {
                    assert_eq!(dek, dummy_dek);
                    assert_eq!(seed, dummy_seed);
                }
            }
            SessionManager::clear_session(test_scope).unwrap();
            let cleared = SessionManager::get_active_keys(test_scope).unwrap();
            assert!(cleared.is_none());
        }
    }

    #[test]
    fn test_crypto_primitives_roundtrip_and_domain_separation() {
        let key = crypto::generate_dek();
        let plaintext = b"secret-cryptographic-payload";
        let (nonce, ciphertext) = crypto::encrypt(&key, plaintext).unwrap();
        let decrypted = crypto::decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        let mut corrupted_ct = ciphertext.clone();
        corrupted_ct[0] ^= 0x01;
        assert!(crypto::decrypt(&key, &nonce, &corrupted_ct).is_err());

        let scope_dek_a = crypto::derive_scope_dek(&key, "proj", "base");
        let scope_dek_b = crypto::derive_scope_dek(&key, "proj", "prod");
        assert_ne!(*scope_dek_a, *scope_dek_b);
        let var_key_1 = crypto::derive_entry_key(&scope_dek_a, "VAR_1");
        let var_key_2 = crypto::derive_entry_key(&scope_dek_a, "VAR_2");
        assert_ne!(*var_key_1, *var_key_2);
    }

    #[test]
    fn test_global_vault_link_and_upward_resolution() {
        let temp_parent = tempdir().unwrap();
        let child_dir = temp_parent.path().join("sub").join("nested");
        fs::create_dir_all(&child_dir).unwrap();
        let env = TestEnv::new("seal-encrypted.toml");
        Vault::init(vec![env.recipient.clone()], false, true, None).unwrap();
        let mut vault = Vault::load_from_file(&env.vault_path).unwrap();
        let keys = vault.unlock(true).unwrap();

        // links current process dir; upgrade path: pass link dir explicitly to link_group
        let prev_dir = env::current_dir().unwrap();
        env::set_current_dir(temp_parent.path()).unwrap();
        vault.link_group(&keys.signing_key, "microservice").unwrap();
        vault.save().unwrap();

        env::set_current_dir(&child_dir).unwrap();
        let resolved = vault.resolve_group_name(None).unwrap();
        assert_eq!(resolved, "microservice");
        env::set_current_dir(prev_dir).unwrap();
    }

    #[test]
    fn toml_vault_hex_and_tables_roundtrip() {
        let mut vault = Vault::default();
        vault.recipients = vec!["age1testrecipient".to_string()];
        vault.envelope = "test-envelope".to_string();
        vault.public_key = vec![0x01, 0x02, 0x03, 0x04];
        vault.signature = vec![0xaa, 0xbb];
        vault
            .entries
            .insert(LOCAL_GROUP_NAME.to_string(), Group::default());
        let raw_toml = toml::to_string_pretty(&vault).expect("serialization failed");
        assert!(raw_toml.contains("age1testrecipient"));
        assert!(raw_toml.contains("public_key = \"01020304\""));
        assert!(raw_toml.contains("signature = \"aabb\""));
        let parsed: Vault = toml::from_str(&raw_toml).expect("deserialization failed");
        assert_eq!(vault, parsed);
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

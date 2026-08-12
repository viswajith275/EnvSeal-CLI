#[cfg(test)]
mod vault_integration_tests {
    use envseal::utils::vault::{Entry, Vault};
    use std::env;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use tempfile::tempdir;

    // Mutex to prevent race conditions when multiple test threads modify the environment variable
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn setup_isolated_env(temp_path: &Path, filename: &str) -> PathBuf {
        let vault_path = temp_path.join(filename);
        env::set_var("ENVSEAL_TEST_PATH", vault_path.to_str().unwrap());
        vault_path
    }

    #[test]
    fn test_vault_initialization_and_overwrite_protection() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        let _path = setup_isolated_env(temp.path(), ".envseal");

        // Successful initialization
        let init_result = Vault::init("master_pass", true, false, None);
        assert!(init_result.is_ok(), "Vault should initialize successfully");

        // Edge Case: Prevent overwriting an existing vault
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
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        // Ensure successful unlock first
        assert!(vault.unlock("master_pass").is_ok());

        vault
            .set_entry(&keys, None, None, "API_KEY", "secret-123", None)
            .unwrap();

        // Edge Case: Simulate file tampering. The vault is persisted as MessagePack,
        // not JSON, so we tamper by mutating the in-memory structure directly
        // (bypassing seal_integrity/signing) and writing it straight to disk via
        // the public save() method. This mimics an attacker editing the sealed
        // file without holding the signing key.
        vault.entries.get_mut("project").unwrap().base.insert(
            "INJECTED_KEY".to_string(),
            Entry {
                nonce: vec![0u8; 12],
                ciphertext: vec![0u8; 16],
            },
        );
        vault.save().unwrap();

        // Load and verify signature failure
        let tampered_vault = Vault::load(false, None).unwrap();
        let unlock_result = tampered_vault.unlock("master_pass");

        assert!(unlock_result.is_err());
        assert!(unlock_result
            .unwrap_err()
            .to_string()
            .contains("SEAL TAMPERED: Ed25519 signature verification failed!!"));
    }

    #[test]
    fn test_base_and_protected_tag_workflow() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        // Set and Get in BASE tag
        vault
            .set_entry(&keys, None, None, "API_KEY", "secret-123", None)
            .unwrap();
        let retrieved = vault
            .get_entry(&keys.master_dek, None, None, "API_KEY", None)
            .unwrap();
        assert_eq!(retrieved.as_str(), "secret-123");

        // Create Protected Tag
        vault
            .create_protected_tag(&keys.signing_key, None, "prod", "tag_pass")
            .unwrap();
        assert!(vault.is_tag_protected(None, Some("prod")).unwrap());

        // Edge Case: Prevent creating a tag named "base"
        let create_base_err = vault.create_protected_tag(&keys.signing_key, None, "base", "pass");
        assert!(create_base_err.is_err());
        assert!(create_base_err
            .unwrap_err()
            .to_string()
            .contains("reserved keyword"));

        // Edge Case: Prevent creating a duplicate tag
        let dup_err = vault.create_protected_tag(&keys.signing_key, None, "prod", "tag_pass");
        assert!(dup_err.is_err());
        assert!(dup_err.unwrap_err().to_string().contains("already exists"));

        // Set and Get in Protected Tag
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
    }

    #[test]
    fn test_entry_removal_edge_cases() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "KEY1", "val1", None)
            .unwrap();

        // Edge Case: Prevent removing the entire 'base' tag
        let remove_base_err = vault.remove_entry(&keys.signing_key, None, Some("base"), None, None);
        assert!(remove_base_err.is_err());
        assert!(remove_base_err
            .unwrap_err()
            .to_string()
            .contains("Cannot remove the reserved"));

        // Successful specific entry removal
        vault
            .remove_entry(&keys.signing_key, None, None, Some("KEY1"), None)
            .unwrap();
        let get_err = vault.get_entry(&keys.master_dek, None, None, "KEY1", None);
        assert!(get_err.is_err());
    }

    #[test]
    fn test_local_vault_group_isolation() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();

        // Edge Case: Local vaults reject explicit group requests
        let resolve_err = vault.resolve_group_name(Some("CUSTOM_GROUP"));
        assert!(resolve_err.is_err());
        assert!(resolve_err
            .unwrap_err()
            .to_string()
            .contains("do not support multiple groups"));

        // Edge Case: Local vaults reject `link_group`
        let keys = vault.unlock("master_pass").unwrap();
        let link_err = vault.link_group(&keys.signing_key, "NEW_GROUP");
        assert!(link_err.is_err());
        assert!(link_err
            .unwrap_err()
            .to_string()
            .contains("Linking is only used for the global vault"));
    }

    #[test]
    fn test_failed_authentication_attempts() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

        Vault::init("correct_master", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();

        // Edge Case: Wrong Master Password
        let bad_master_err = vault.unlock("wrong_master");
        assert!(bad_master_err.is_err());
        assert!(bad_master_err
            .unwrap_err()
            .to_string()
            .contains("Wrong master password"));

        // Edge Case: Wrong Tag Password
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
    fn test_custom_profile_naming() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        let path = setup_isolated_env(temp.path(), ".prod.envseal");

        // Init with custom prefix (e.g. -e prod -> .prod.envseal)
        Vault::init("master_pass", true, false, Some("prod")).unwrap();
        assert!(path.exists());

        // Load custom profile and verify is_local() recognizes it
        let vault = Vault::load(false, Some("prod")).unwrap();
        assert!(vault.is_local());
    }

    #[test]
    fn test_list_all_keys() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

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

        // List base keys
        let base_keys = vault.list_all_keys(None, None).unwrap();
        assert_eq!(base_keys.len(), 2);
        assert!(base_keys.contains(&"BASE_KEY_1".to_string()));

        // List tag keys (merged with base, per current list_all_keys behavior)
        let dev_keys = vault.list_all_keys(None, Some("dev")).unwrap();
        assert_eq!(dev_keys.len(), 3);
        assert!(dev_keys.contains(&"DEV_KEY_1".to_string()));
        assert!(dev_keys.contains(&"BASE_KEY_1".to_string()));
    }

    #[test]
    fn test_protected_tag_deletion_rules() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .create_protected_tag(&keys.signing_key, None, "secure_tag", "tag_pass")
            .unwrap();

        // Edge Case: Modifying/Deleting inside a protected tag without password must fail
        let unauth_remove_err =
            vault.remove_entry(&keys.signing_key, None, Some("secure_tag"), None, None);
        assert!(unauth_remove_err.is_err());
        assert!(unauth_remove_err
            .unwrap_err()
            .to_string()
            .contains("Password required to modify it"));

        // Successful tag deletion with valid tag key unlocked
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

        // Verify tag no longer exists
        assert!(!vault.is_tag_protected(None, Some("secure_tag")).unwrap());
    }

    #[test]
    fn test_master_and_tag_scope_generation() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        let _ = setup_isolated_env(temp.path(), ".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let vault = Vault::load(false, None).unwrap();

        // Master scope should be a deterministic hash starting with "master_"
        let scope = vault.master_scope();
        assert!(scope.starts_with("master_"));

        // Tag scope should append group and tag names
        let tag_scope = vault.tag_scope(None, "dev").unwrap();
        assert!(tag_scope.contains("group_project_tag_dev"));
    }

    #[test]
    fn test_rotate_base_scope_dek() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        vault
            .set_entry(&keys, None, None, "API_KEY", "secret-123", None)
            .unwrap();

        // Rotate the base scope DEK. This re-wraps the master DEK, so the
        // VaultKeys held before rotation becomes stale for decrypting entries.
        vault
            .rotate_scope_dek(&keys, None, None, None, None)
            .unwrap();

        // Re-unlocking with the same master password must still succeed and
        // must yield keys that can decrypt the rotated entry correctly.
        let rotated_keys = vault.unlock("master_pass").unwrap();
        let retrieved = vault
            .get_entry(&rotated_keys.master_dek, None, None, "API_KEY", None)
            .unwrap();
        assert_eq!(retrieved.as_str(), "secret-123");
    }

    #[test]
    fn test_rotate_protected_tag_dek_requires_password() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let mut vault = Vault::load(false, None).unwrap();
        let keys = vault.unlock("master_pass").unwrap();

        // An empty protected tag: no entries to decrypt, so rotation must
        // fail directly on the missing tag password rather than on entry
        // decryption.
        vault
            .create_protected_tag(&keys.signing_key, None, "prod", "tag_pass")
            .unwrap();

        let rotate_no_pass = vault.rotate_scope_dek(&keys, None, Some("prod"), None, None);
        assert!(rotate_no_pass.is_err());
        assert!(rotate_no_pass
            .unwrap_err()
            .to_string()
            .contains("Tag password required"));
    }

    #[test]
    fn test_rotate_protected_tag_dek_with_entries() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        setup_isolated_env(temp.path(), ".envseal");

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

        // Edge Case: rotating a tag with existing entries but no supplied
        // tag DEK fails while re-reading the entries, before the password
        // itself is even checked.
        let rotate_no_dek =
            vault.rotate_scope_dek(&keys, None, Some("prod"), None, Some("tag_pass"));
        assert!(rotate_no_dek.is_err());
        assert!(rotate_no_dek
            .unwrap_err()
            .to_string()
            .contains("Password required for protected tag"));

        // Rotating a protected tag's DEK requires both the current tag DEK
        // (to re-encrypt existing entries) and the tag password (to rewrap
        // the new DEK). The salt, and therefore the tag password itself,
        // stays the same afterward.
        vault
            .rotate_scope_dek(&keys, None, Some("prod"), Some(&tag_key), Some("tag_pass"))
            .unwrap();

        // Unlocking with the same tag password after rotation still works,
        // and yields the newly rotated tag DEK that decrypts correctly.
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
}

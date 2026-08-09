#[cfg(test)]
mod vault_integration_tests {
    use envseal::utils::vault::Vault;
    use std::env;
    use std::fs;
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
            .contains("Refusing to overwrite"));
    }

    #[test]
    fn test_hmac_tamper_detection() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp = tempdir().unwrap();
        let path = setup_isolated_env(temp.path(), ".envseal");

        Vault::init("master_pass", true, false, None).unwrap();
        let vault = Vault::load(false, None).unwrap();

        // Ensure successful unlock first
        assert!(vault.unlock("master_pass").is_ok());

        // Edge Case: Simulate file tampering (user modifies JSON manually)
        let raw_json = fs::read_to_string(&path).unwrap();
        // Tamper with the cleartext JSON structure (modifying the implicitly created "project" group)
        let tampered_json = raw_json.replace("\"project\"", "\"hacked_project\"");
        fs::write(&path, tampered_json).unwrap();

        // Load and verify HMAC failure
        let tampered_vault = Vault::load(false, None).unwrap();
        let unlock_result = tampered_vault.unlock("master_pass");

        assert!(unlock_result.is_err());
        assert!(unlock_result
            .unwrap_err()
            .to_string()
            .contains("SEAL TAMPERED: HMAC verification failed!"));
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
            .get_entry(&keys.enc_key, None, None, "API_KEY", None)
            .unwrap();
        assert_eq!(retrieved.as_str(), "secret-123");

        // Create Protected Tag
        vault
            .create_protected_tag(&keys.hmac_key, None, "prod", "tag_pass")
            .unwrap();
        assert!(vault.is_tag_protected(None, Some("prod")).unwrap());

        // Edge Case: Prevent creating a tag named "base"
        let create_base_err = vault.create_protected_tag(&keys.hmac_key, None, "base", "pass");
        assert!(create_base_err.is_err());
        assert!(create_base_err
            .unwrap_err()
            .to_string()
            .contains("reserved keyword"));

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
            .get_entry(&keys.enc_key, None, Some("prod"), "DB_PASS", Some(&tag_key))
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
        let remove_base_err = vault.remove_entry(&keys.hmac_key, None, Some("base"), None, None);
        assert!(remove_base_err.is_err());
        assert!(remove_base_err
            .unwrap_err()
            .to_string()
            .contains("Cannot remove the reserved"));

        // Successful specific entry removal
        vault
            .remove_entry(&keys.hmac_key, None, None, Some("KEY1"), None)
            .unwrap();
        let get_err = vault.get_entry(&keys.enc_key, None, None, "KEY1", None);
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
        let link_err = vault.link_group(&keys.hmac_key, "NEW_GROUP");
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
            .contains("Wrong Master Password"));

        // Edge Case: Wrong Tag Password
        let keys = vault.unlock("correct_master").unwrap();
        vault
            .create_protected_tag(&keys.hmac_key, None, "staging", "correct_tag_pass")
            .unwrap();

        let bad_tag_err = vault.unlock_tag(None, "staging", "wrong_tag_pass");
        assert!(bad_tag_err.is_err());
        assert!(bad_tag_err
            .unwrap_err()
            .to_string()
            .contains("Wrong Tag Password"));
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
            .create_protected_tag(&keys.hmac_key, None, "dev", "tag_pass")
            .unwrap();
        let tag_key = vault.unlock_tag(None, "dev", "tag_pass").unwrap();
        vault
            .set_entry(&keys, None, Some("dev"), "DEV_KEY_1", "v3", Some(&tag_key))
            .unwrap();

        // List base keys
        let base_keys = vault.list_all_keys(None, None).unwrap();
        assert_eq!(base_keys.len(), 2);
        assert!(base_keys.contains(&"BASE_KEY_1".to_string()));

        // List tag keys
        let dev_keys = vault.list_all_keys(None, Some("dev")).unwrap();
        assert_eq!(dev_keys.len(), 1);
        assert!(dev_keys.contains(&"DEV_KEY_1".to_string()));
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
            .create_protected_tag(&keys.hmac_key, None, "secure_tag", "tag_pass")
            .unwrap();

        // Edge Case: Modifying/Deleting inside a protected tag without password must fail
        let unauth_remove_err =
            vault.remove_entry(&keys.hmac_key, None, Some("secure_tag"), None, None);
        assert!(unauth_remove_err.is_err());
        assert!(unauth_remove_err
            .unwrap_err()
            .to_string()
            .contains("Password required to modify it"));

        // Successful tag deletion with valid tag key unlocked
        let tag_key = vault.unlock_tag(None, "secure_tag", "tag_pass").unwrap();
        vault
            .remove_entry(
                &keys.hmac_key,
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
}

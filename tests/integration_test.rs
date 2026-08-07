use envseal::utils::crypto;
use envseal::utils::vault::Vault;
use serial_test::serial;
use std::env;
use tempfile::TempDir;

// Helper function to set up isolated test environments using a TempDir
fn setup_test_vault() -> TempDir {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    // Point the environment variable to a file inside the temp directory that DOES NOT exist yet
    let vault_path = temp_dir.path().join("vault.seal");
    env::set_var("ENVSEAL_TEST_PATH", vault_path);

    // Return the directory guard so it stays alive until the end of the test
    temp_dir
}

#[test]
fn test_crypto_flow() {
    let password = "super_secure_password";
    let salt = crypto::generate_salt();
    let (enc_key, hmac_key) = crypto::derive_keys(password, &salt).expect("Failed to derive key");
    let plaintext = "secret_api_key";

    let (nonce, ciphertext) = crypto::encrypt(&enc_key, plaintext).expect("Encryption failed");
    let decrypted = crypto::decrypt(&enc_key, &nonce, &ciphertext).expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[test]
#[serial]
fn test_vault_init_and_unlock() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";

    Vault::init(password).expect("Failed to init vault");
    let vault = Vault::load().expect("Failed to load vault");

    let keys = vault
        .unlock(password)
        .expect("Failed to unlock vault with correct password");
    assert_eq!(keys.enc_key.len(), crypto::KEY_LEN);
    assert_eq!(keys.hmac_key.len(), crypto::HMAC_KEY_LEN);

    let bad_unlock = vault.unlock("wrong_password");
    assert!(bad_unlock.is_err());
}

#[test]
#[serial]
fn test_vault_init_prevents_overwrite() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";

    Vault::init(password).expect("First init failed");
    let second_init = Vault::init(password);
    assert!(
        second_init.is_err(),
        "Seal::init should error out if a seal already exists to prevent data loss"
    );
}

#[test]
#[serial]
fn test_vault_set_and_get_entry() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";

    Vault::init(password).expect("Failed to init vault");
    let mut vault = Vault::load().expect("Failed to load vault");
    let keys = vault.unlock(password).expect("Failed to unlock vault");

    let group_name = "test_project";
    vault
        .link_group(&keys.hmac_key, group_name.to_string())
        .expect("Failed to link group");

    vault
        .set_entry(
            &keys,
            Some(group_name),
            None,
            false,
            "DB_HOST",
            "localhost",
            None,
        )
        .expect("Failed to set entry");

    let retrieved_value = vault
        .get_entry(
            &keys.enc_key,
            Some(group_name),
            None,
            "DB_HOST",
            false,
            None,
        )
        .expect("Failed to get entry");

    assert_eq!(retrieved_value, "localhost");
}

#[test]
#[serial]
fn test_vault_overwrite_entry() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";

    Vault::init(password).unwrap();
    let mut vault = Vault::load().unwrap();
    let keys = vault.unlock(password).unwrap();

    let group_name = "test_project";
    vault
        .link_group(&keys.hmac_key, group_name.to_string())
        .unwrap();

    // Set initial value
    vault
        .set_entry(&keys, Some(group_name), None, false, "PORT", "8080", None)
        .unwrap();

    // Overwrite with new value
    vault
        .set_entry(&keys, Some(group_name), None, false, "PORT", "9090", None)
        .unwrap();

    let retrieved = vault
        .get_entry(&keys.enc_key, Some(group_name), None, "PORT", false, None)
        .unwrap();
    assert_eq!(retrieved, "9090", "Vault should overwrite existing keys");
}

#[test]
fn test_crypto_tampering_fails_decryption() {
    let password = "super_secure_password";
    let salt = crypto::generate_salt();
    let (enc_key, _hmac_key) = crypto::derive_keys(password, &salt).unwrap();
    let plaintext = "secret_api_key";

    let (nonce, mut ciphertext) = crypto::encrypt(&enc_key, plaintext).unwrap();

    if let Some(first_byte) = ciphertext.first_mut() {
        *first_byte ^= 1;
    }

    let decrypted = crypto::decrypt(&enc_key, &nonce, &ciphertext);
    assert!(
        decrypted.is_err(),
        "Decryption must fail if the ciphertext has been modified"
    );
}

#[test]
#[serial]
fn test_vault_with_tags() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";

    Vault::init(password).unwrap();
    let mut vault = Vault::load().unwrap();
    let keys = vault.unlock(password).unwrap();

    let group_name = "test_project";
    vault
        .link_group(&keys.hmac_key, group_name.to_string())
        .unwrap();

    // Set same key with different tags
    vault
        .set_entry(
            &keys,
            Some(group_name),
            Some("development"),
            false,
            "API_KEY",
            "dev_123",
            None,
        )
        .unwrap();
    vault
        .set_entry(
            &keys,
            Some(group_name),
            Some("production"),
            false,
            "API_KEY",
            "prod_999",
            None,
        )
        .unwrap();

    let dev_val = vault
        .get_entry(
            &keys.enc_key,
            Some(group_name),
            Some("development"),
            "API_KEY",
            false,
            None,
        )
        .unwrap();
    let prod_val = vault
        .get_entry(
            &keys.enc_key,
            Some(group_name),
            Some("production"),
            "API_KEY",
            false,
            None,
        )
        .unwrap();

    assert_eq!(dev_val, "dev_123");
    assert_eq!(prod_val, "prod_999");
}

#[test]
#[serial]
fn test_vault_get_missing_entry() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";

    Vault::init(password).unwrap();
    let mut vault = Vault::load().unwrap();
    let keys = vault.unlock(password).unwrap();

    let group_name = "test_project";
    vault
        .link_group(&keys.hmac_key, group_name.to_string())
        .unwrap();

    let result = vault.get_entry(
        &keys.enc_key,
        Some(group_name),
        None,
        "NON_EXISTENT",
        false,
        None,
    );
    assert!(
        result.is_err(),
        "Fetching a missing key should return an error"
    );
}

#[test]
#[serial]
fn test_vault_persistence_across_reloads() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";
    let group_name = "test_project";

    Vault::init(password).unwrap();
    {
        let mut vault = Vault::load().unwrap();
        let keys = vault.unlock(password).unwrap();
        vault
            .link_group(&keys.hmac_key, group_name.to_string())
            .unwrap();
        vault
            .set_entry(
                &keys,
                Some(group_name),
                None,
                false,
                "DB_URL",
                "postgres://localhost",
                None,
            )
            .unwrap();
        vault.save().unwrap();
    }

    let vault = Vault::load().unwrap();
    let keys = vault.unlock(password).unwrap();

    let retrieved = vault
        .get_entry(&keys.enc_key, Some(group_name), None, "DB_URL", false, None)
        .unwrap();
    assert_eq!(retrieved, "postgres://localhost");
}

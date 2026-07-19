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
    let key = crypto::derive_key(password, &salt).expect("Failed to derive key");
    let plaintext = "secret_api_key";

    // Encrypt
    let (nonce, ciphertext) = crypto::encrypt(&key, plaintext).expect("Encryption failed");

    // Decrypt
    let decrypted = crypto::decrypt(&key, &nonce, &ciphertext).expect("Decryption failed");

    // Assert
    assert_eq!(decrypted, plaintext);
}

#[test]
#[serial]
fn test_vault_init_and_unlock() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";

    // Initialize the vault (this will now succeed because the file doesn't exist yet)
    Vault::init(password).expect("Failed to init vault");

    // Load the vault from the filesystem
    let vault = Vault::load().expect("Failed to load vault");

    // Attempt to unlock it with the correct password
    let key = vault
        .unlock(password)
        .expect("Failed to unlock vault with correct password");
    assert_eq!(key.len(), crypto::KEY_LEN);

    // Attempt to unlock with a wrong password
    let bad_unlock = vault.unlock("wrong_password");
    assert!(bad_unlock.is_err());
}

#[test]
#[serial]
fn test_vault_init_prevents_overwrite() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";

    // First init should succeed
    Vault::init(password).expect("First init failed");

    // Second init on the same path should return an Error
    let second_init = Vault::init(password);
    assert!(
        second_init.is_err(),
        "Vault::init should error out if a seal already exists to prevent data loss"
    );
}

#[test]
#[serial]
fn test_vault_set_and_get_entry() {
    let _temp_dir = setup_test_vault();
    let password = "master_password";

    Vault::init(password).expect("Failed to init vault");
    let mut vault = Vault::load().expect("Failed to load vault");
    let key = vault.unlock(password).expect("Failed to unlock vault");

    // Link a group
    let group_name = "test_project".to_string();
    vault
        .link_group(group_name.clone())
        .expect("Failed to link group");

    // Set an entry in the "base" tag (None)
    vault
        .set_entry(
            &key,
            &Some(group_name.clone()),
            &None,
            "DB_HOST",
            "localhost",
        )
        .expect("Failed to set entry");

    // Retrieve the entry
    let retrieved_value = vault
        .get_entry(&key, &Some(group_name.clone()), &None, "DB_HOST")
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
    let key = vault.unlock(password).unwrap();

    let group = Some("test_project".to_string());
    vault.link_group("test_project".to_string()).unwrap();

    // Set initial value
    vault
        .set_entry(&key, &group, &None, "PORT", "8080")
        .unwrap();

    // Overwrite with new value
    vault
        .set_entry(&key, &group, &None, "PORT", "9090")
        .unwrap();

    let retrieved = vault.get_entry(&key, &group, &None, "PORT").unwrap();
    assert_eq!(retrieved, "9090", "Vault should overwrite existing keys");
}

#[test]
fn test_crypto_tampering_fails_decryption() {
    let password = "super_secure_password";
    let salt = crypto::generate_salt();
    let key = crypto::derive_key(password, &salt).unwrap();
    let plaintext = "secret_api_key";

    let (nonce, mut ciphertext) = crypto::encrypt(&key, plaintext).unwrap();

    // Flip a single bit in the ciphertext to simulate tampering or corruption
    if let Some(first_byte) = ciphertext.first_mut() {
        *first_byte ^= 1;
    }

    // Decryption should now fail
    let decrypted = crypto::decrypt(&key, &nonce, &ciphertext);
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
    let key = vault.unlock(password).unwrap();

    let group = Some("test_project".to_string());
    vault.link_group("test_project".to_string()).unwrap();

    let dev_tag = Some("development".to_string());
    let prod_tag = Some("production".to_string());

    // Set same key with different tags
    vault
        .set_entry(&key, &group, &dev_tag, "API_KEY", "dev_123")
        .unwrap();
    vault
        .set_entry(&key, &group, &prod_tag, "API_KEY", "prod_999")
        .unwrap();

    let dev_val = vault.get_entry(&key, &group, &dev_tag, "API_KEY").unwrap();
    let prod_val = vault.get_entry(&key, &group, &prod_tag, "API_KEY").unwrap();

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
    let key = vault.unlock(password).unwrap();

    let group = Some("test_project".to_string());
    vault.link_group("test_project".to_string()).unwrap();

    // Attempt to get a key that doesn't exist
    let result = vault.get_entry(&key, &group, &None, "NON_EXISTENT");

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
    let group = Some("test_project".to_string());

    // 1. Init, set data, and (presumably) drop/save
    Vault::init(password).unwrap();
    {
        let mut vault = Vault::load().unwrap();
        let key = vault.unlock(password).unwrap();
        vault.link_group("test_project".to_string()).unwrap();
        vault
            .set_entry(&key, &group, &None, "DB_URL", "postgres://localhost")
            .unwrap();
        vault.save().unwrap();
    }

    //Completely reload the vault from disk in a new scope
    let vault = Vault::load().unwrap();
    let key = vault.unlock(password).unwrap();

    // Verify the data persisted
    let retrieved = vault.get_entry(&key, &group, &None, "DB_URL").unwrap();
    assert_eq!(retrieved, "postgres://localhost");
}

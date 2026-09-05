pub mod crypto;
pub mod envelope;
pub mod git;
pub mod resolve;
pub mod session;
pub mod token;
pub mod unlock;
pub mod vault;

// just checking if the key is valid or not
pub fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

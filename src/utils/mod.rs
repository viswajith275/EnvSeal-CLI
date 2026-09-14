pub mod crypto;
pub mod envelope;
pub mod git;
pub mod resolve;
pub mod session;
pub mod token;
pub mod unlock;
pub mod vault;

use std::borrow::Cow;

// just checking if the key is valid or not
pub fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn format_env_value(value: &str) -> Cow<'_, str> {
    if value.chars().any(|c| {
        matches!(
            c,
            ' ' | '\t' | '\n' | '\r' | '"' | '\'' | '#' | '$' | '`' | '\\'
        )
    }) {
        Cow::Owned(format!("'{}'", value.replace('\'', "'\\''")))
    } else {
        Cow::Borrowed(value)
    }
}

pub fn parse_env_lines(raw: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let line_clean = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some((k, v)) = line_clean.split_once('=') {
            let key = k.trim();
            if !is_valid_env_key(key) {
                eprintln!("Warning: skipping invalid key '{key}!!'");
                continue;
            }
            let val = v.trim().trim_matches(|c| c == '"' || c == '\'');
            entries.push((key.to_string(), val.to_string()));
        }
    }
    entries
}

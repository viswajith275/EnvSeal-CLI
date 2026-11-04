pub mod crypto;
pub mod envelope;
pub mod git;
pub mod resolve;
pub mod session;
pub mod token;
pub mod unlock;
pub mod vault;

use std::borrow::Cow;
use std::fs::OpenOptions;
use std::io::Write;
use tempfile::NamedTempFile;

pub struct ShredOnDrop(pub NamedTempFile);

impl Drop for ShredOnDrop {
    fn drop(&mut self) {
        if let Ok(mut f) = OpenOptions::new().write(true).open(self.0.path()) {
            if let Ok(meta) = f.metadata() {
                let zeroes = vec![0u8; meta.len() as usize];
                let _ = f.write_all(&zeroes);
                let _ = f.sync_all();
            }
        }
    }
}

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

fn unquote(v: &str) -> String {
    let s = v.trim();
    if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        inner.replace("'\\''", "'")
    } else if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        s.to_string()
    }
}

pub fn parse_env_lines(raw: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut lines = raw.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let line_clean = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some((k, v)) = line_clean.split_once('=') {
            let key = k.trim();
            if !is_valid_env_key(key) {
                eprintln!("Warning: skipping invalid key '{key}'.");
                continue;
            }
            let mut val_str = v.trim().to_string();

            let starts_single =
                val_str.starts_with('\'') && (!val_str.ends_with('\'') || val_str.len() == 1);
            let starts_double =
                val_str.starts_with('"') && (!val_str.ends_with('"') || val_str.len() == 1);

            if starts_single || starts_double {
                let quote_char = if starts_single { '\'' } else { '"' };
                for next_line in lines.by_ref() {
                    val_str.push('\n');
                    val_str.push_str(next_line);
                    if next_line.trim_end().ends_with(quote_char) {
                        break;
                    }
                }
            }

            let val = unquote(&val_str);
            entries.push((key.to_string(), val));
        }
    }
    entries
}

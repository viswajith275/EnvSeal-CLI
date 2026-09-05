use age::secrecy::ExposeSecret;
use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

fn home_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
}

fn envseal_identity_path() -> Option<PathBuf> {
    ProjectDirs::from("dev", "envseal", "envseal")
        .map(|dirs| dirs.config_dir().join("identity.txt"))
}

// identity file permissions use standard 0600 on Unix, but rely on default folder ACLs on Windows.
pub fn get_or_create_default_recipient() -> Result<String> {
    // Check existing SSH public keys
    if let Some(home) = home_dir() {
        for name in &["id_ed25519.pub", "id_rsa.pub"] {
            let pub_path = home.join(".ssh").join(name);
            if pub_path.exists() {
                return Ok(fs::read_to_string(pub_path)?.trim().to_string());
            }
        }
    }

    // Check existing envseal identity file
    let id_path = envseal_identity_path()
        .ok_or_else(|| anyhow!("Could not determine OS config directory"))?;

    if id_path.exists() {
        let contents = fs::read_to_string(&id_path)?;
        for line in contents.lines() {
            let trimmed = line.trim();
            if let Ok(id) = trimmed.parse::<age::x25519::Identity>() {
                return Ok(id.to_public().to_string());
            }
        }
    }

    // Fallback: Generate fresh Age identity inside envseal's config dir
    if let Some(parent) = id_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let identity = age::x25519::Identity::generate();
    let pubkey = identity.to_public().to_string();
    let secret = identity.to_string();

    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&id_path)?;
    writeln!(file, "# created by envseal")?;
    writeln!(file, "# public key: {pubkey}")?;
    writeln!(file, "{}", secret.expose_secret())?;

    eprintln!("[envseal] Generated new identity at {}", id_path.display());

    Ok(pubkey)
}

pub fn discover_default_identities(allow_env: bool) -> Vec<Box<dyn age::Identity>> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
    let mut files = Vec::new();

    if allow_env {
        if let Ok(raw) = std::env::var("ENVSEAL_IDENTITY") {
            if let Ok(id) = raw.trim().parse::<age::x25519::Identity>() {
                identities.push(Box::new(id));
            }
        }
        if let Ok(path) = std::env::var("ENVSEAL_IDENTITY_FILE") {
            let p = PathBuf::from(path);
            if p.exists() {
                files.push(p.display().to_string());
            }
        }
    }

    if let Some(home) = home_dir() {
        for candidate in &[home.join(".ssh/id_ed25519"), home.join(".ssh/id_rsa")] {
            if candidate.exists() {
                files.push(candidate.display().to_string());
            }
        }
    }

    if let Some(id_path) = envseal_identity_path() {
        if id_path.exists() {
            files.push(id_path.display().to_string());
        }
    }

    if !files.is_empty() {
        let mut stdin_guard = age::cli_common::StdinGuard::new(false);
        if let Ok(discovered) = age::cli_common::read_identities(files, None, &mut stdin_guard) {
            identities.extend(discovered);
        }
    }

    identities
}

pub fn unwrap_envelope(
    armored: &str,
    extra_identity: Option<Box<dyn age::Identity>>,
    allow_env: bool,
) -> Result<Zeroizing<[u8; 64]>> {
    let mut identities = discover_default_identities(allow_env);

    if let Some(id) = extra_identity {
        identities.push(id);
    }

    if identities.is_empty() {
        return Err(anyhow!(
            "Access Denied: No identity found. Ensure ~/.ssh/id_ed25519 exists or set ENVSEAL_IDENTITY"
        ));
    }

    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(armored.as_bytes()))?;

    let id_refs: Vec<&dyn age::Identity> = identities
        .iter()
        .map(|i| &**i as &dyn age::Identity)
        .collect();

    let mut reader = decryptor
        .decrypt(id_refs.into_iter())
        .map_err(|_| anyhow!("Access Denied: Identity not authorized for this environment"))?;

    let mut decrypted = [0u8; 64];
    reader.read_exact(&mut decrypted)?;
    Ok(Zeroizing::new(decrypted))
}

pub fn wrap_envelope(payload: &[u8; 64], recipient_strings: &[String]) -> Result<String> {
    let mut recipients: Vec<Box<dyn age::Recipient>> = Vec::new();

    for r in recipient_strings {
        let clean = r.split('#').next().unwrap_or(r).trim();
        if let Ok(pubkey) = clean.parse::<age::x25519::Recipient>() {
            recipients.push(Box::new(pubkey));
        } else if let Ok(pubkey) = clean.parse::<age::ssh::Recipient>() {
            recipients.push(Box::new(pubkey));
        } else {
            return Err(anyhow!("Invalid recipient format: '{r}'"));
        }
    }

    if recipients.is_empty() {
        return Err(anyhow!("Vault must have at least one recipient"));
    }

    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| &**r as &dyn age::Recipient))
            .context("Failed to configure age encryptor")?;

    let mut output = Vec::new();
    let armor_writer =
        age::armor::ArmoredWriter::wrap_output(&mut output, age::armor::Format::AsciiArmor)?;
    let mut writer = encryptor.wrap_output(armor_writer)?;
    writer.write_all(payload)?;
    writer.finish()?.finish()?;

    String::from_utf8(output).context("Armor payload is not valid UTF-8")
}

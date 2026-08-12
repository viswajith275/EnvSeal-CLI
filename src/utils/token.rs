use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
pub enum TokenKeyMaterial {
    /// Token holds ONLY the pre-derived keys for specific variables
    GranularKeys(HashMap<String, Zeroizing<Vec<u8>>>),
}
#[derive(Serialize, Deserialize)]
pub struct TokenPayload {
    /// Scope (e.g, "group_project_tag_prod")
    pub scope: String,
    /// key material
    pub key_material: TokenKeyMaterial,
    /// Identity of the token creator / reason for creation
    pub sub: String,
    /// Issued at timestamp
    pub iat: u64,
    /// Expiration time of token (Dont trust this can be manipulated)
    pub exp: Option<u64>,
    /// Custom description
    pub description: Option<String>,
}

pub struct TokenManager;

impl TokenManager {
    /// Creates a new Bearer Token
    pub fn create(
        signing_key: &SigningKey,
        scope: &str,
        keys: HashMap<String, Zeroizing<Vec<u8>>>,
        sub: &str,
        ttl_seconds: Option<u64>,
        description: Option<&str>,
    ) -> Result<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let expiry_time = if ttl_seconds.is_some() {
            Some(now + ttl_seconds.unwrap())
        } else {
            None
        };
        let payload = TokenPayload {
            scope: scope.to_string(),
            key_material: TokenKeyMaterial::GranularKeys(keys),
            sub: sub.to_string(),
            iat: now,
            exp: expiry_time,
            description: description.map(|s| s.to_string()),
        };

        let json_bytes = serde_json::to_vec(&payload)?;

        let compressed_payload = zstd::encode_all(json_bytes.as_slice(), 3)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(&compressed_payload);

        let signature = signing_key.sign(payload_b64.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("envseal_{}.{}", payload_b64, signature_b64))
    }

    pub fn verify_and_extract(token_str: &str, public_key: &[u8]) -> Result<TokenPayload> {
        let clean_token = token_str.trim_start_matches("envseal_");
        let parts: Vec<&str> = clean_token.split('.').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid token format!!"));
        }

        let (payload_b64, signature_b64) = (parts[0], parts[1]);

        let verifying_key = VerifyingKey::from_bytes(public_key.try_into()?)?;
        let sign_bytes = URL_SAFE_NO_PAD.decode(signature_b64)?;
        let signature = Signature::from_bytes(sign_bytes.as_slice().try_into()?);

        verifying_key
            .verify(payload_b64.as_bytes(), &signature)
            .map_err(|_| anyhow!("ACCESS DENIED: Token signature verification failed!!"))?;

        let compressed_payload = URL_SAFE_NO_PAD.decode(payload_b64)?;
        let json_bytes = zstd::decode_all(compressed_payload.as_slice())
            .map_err(|_| anyhow!("Failed to decompress token payload!"))?;

        let payload: TokenPayload = serde_json::from_slice(&json_bytes)?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if payload.exp.is_some() {
            if now > payload.exp.unwrap() {
                return Err(anyhow!(
                    "Token expired, Create a new one to continue using!!"
                ));
            }
        }

        Ok(payload)
    }
}

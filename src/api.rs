//! Key requests to dashcam.tesla.com.
//!
//! The official viewer posts ownership metadata from each clip header and gets
//! back a per-file AES key. The encrypted video is not part of the request.

use std::collections::HashMap;

use anyhow::{bail, Context};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::container::ClipHeader;
use crate::net;

/// Live `POST /api/1/decrypt/batch` rejects anything larger with
/// `{"error":"batch size exceeds maximum of 30"}`. The viewer bundle also
/// defines a 300 constant; the server does not honor it.
pub const MAX_BATCH: usize = 30;

#[derive(Debug, Serialize)]
pub struct KeyRequestItem {
    pub id: String,
    pub vin: String,
    pub key_id: u32,
    pub timestamp: u64,
    pub wrapped_key: String,
    pub public_key: String,
}

#[derive(Debug)]
pub struct FetchedKeys {
    pub keys: HashMap<String, Vec<u8>>,
    pub errors: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum FetchError {
    Unauthorized,
    Failed(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "Tesla rejected the access token"),
            Self::Failed(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for FetchError {}

pub fn item_for(header: &ClipHeader) -> KeyRequestItem {
    KeyRequestItem {
        // The viewer sends a client-generated id. Tesla echoes it on the result.
        id: Uuid::new_v4().to_string(),
        vin: header.vin.clone(),
        key_id: header.key_id,
        timestamp: header.timestamp,
        wrapped_key: STANDARD.encode(&header.wrapped_key),
        public_key: STANDARD.encode(&header.public_key),
    }
}

pub fn fetch_keys(
    api_base: &str,
    token: &str,
    items: &[KeyRequestItem],
) -> Result<FetchedKeys, FetchError> {
    if items.is_empty() {
        return Ok(FetchedKeys {
            keys: HashMap::new(),
            errors: Vec::new(),
        });
    }
    if items.len() > MAX_BATCH {
        return Err(FetchError::Failed(format!(
            "batch of {} is above Tesla's limit of {MAX_BATCH}",
            items.len()
        )));
    }

    let client = net::client().map_err(|err| FetchError::Failed(err.to_string()))?;
    let url = format!("{}/api/1/decrypt/batch", api_base.trim_end_matches('/'));
    let response = client
        .post(url)
        .bearer_auth(token.trim())
        .header("Origin", "https://dashcam.tesla.com")
        .header("Referer", "https://dashcam.tesla.com/")
        .json(&BatchBody { items })
        .send()
        .map_err(|err| FetchError::Failed(format!("key request failed: {err}")))?;

    let status = response.status();
    let txid = response
        .headers()
        .get("x-txid")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if status.as_u16() == 401 {
        return Err(FetchError::Unauthorized);
    }
    let body = response
        .text()
        .map_err(|err| FetchError::Failed(format!("reading key response: {err}")))?;
    if !status.is_success() {
        let snippet: String = body.chars().take(400).collect();
        let tx = if txid.is_empty() {
            String::new()
        } else {
            format!(" (txid {txid})")
        };
        return Err(FetchError::Failed(format!(
            "Tesla key request returned {status}{tx}: {snippet}"
        )));
    }

    let parsed: BatchResponse = serde_json::from_str(&body).map_err(|err| {
        FetchError::Failed(format!(
            "Tesla key response was not the expected JSON: {err}"
        ))
    })?;

    let mut keys = HashMap::new();
    let mut errors = Vec::new();
    for result in parsed.results {
        if let Some(err) = result.error {
            if !err.is_null() {
                errors.push((result.id, err.to_string()));
                continue;
            }
        }
        let Some(encoded) = result.key else {
            errors.push((result.id, "response omitted the key".into()));
            continue;
        };
        match decode_key(&encoded) {
            Ok(raw) => {
                keys.insert(result.id, raw);
            }
            Err(err) => errors.push((result.id, err.to_string())),
        }
    }
    Ok(FetchedKeys { keys, errors })
}

fn decode_key(encoded: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = encoded.trim();
    let raw = STANDARD
        .decode(trimmed)
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .context("key was not base64")?;
    if raw.len() != 16 && raw.len() != 32 {
        bail!("decoded key is {} bytes, expected 16 or 32", raw.len());
    }
    Ok(raw)
}

#[derive(Serialize)]
struct BatchBody<'a> {
    items: &'a [KeyRequestItem],
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<KeyResult>,
}

#[derive(Deserialize)]
struct KeyResult {
    id: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uses_the_viewer_field_names() {
        let item = KeyRequestItem {
            id: "11111111-1111-1111-1111-111111111111".into(),
            vin: "5YJ3E1EA7KF000001".into(),
            key_id: 3,
            timestamp: 99,
            wrapped_key: "YWI=".into(),
            public_key: "BA==".into(),
        };
        let value = serde_json::to_value(&item).unwrap();
        assert_eq!(value["id"], "11111111-1111-1111-1111-111111111111");
        assert_eq!(value["vin"], "5YJ3E1EA7KF000001");
        assert_eq!(value["key_id"], 3);
        assert_eq!(value["timestamp"], 99);
        assert_eq!(value["wrapped_key"], "YWI=");
        assert_eq!(value["public_key"], "BA==");
        assert!(value.get("keyId").is_none());
    }

    #[test]
    fn decodes_standard_and_url_safe_keys() {
        let raw = decode_key("AQIDBAUGBwgJCgsMDQ4PEA==").unwrap();
        assert_eq!(raw, (1..=16).collect::<Vec<_>>());
        let raw = decode_key("AQIDBAUGBwgJCgsMDQ4PEA").unwrap();
        assert_eq!(raw, (1..=16).collect::<Vec<_>>());
    }
}

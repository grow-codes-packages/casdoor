// Owned by this repository: Casdoor helpers (error normalization, PKCE, tokens).
//! Casdoor helpers: `{"status":"error"}` / OAuth error normalization, PKCE, tokens.

use std::time::{Duration, SystemTime};

use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::core::{Error, ErrorCode, Result};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_with(bytes: &[u8], url: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..=chunk.len() {
            let c = B64[((n >> (18 - 6 * i)) & 63) as usize] as char;
            out.push(match (url, c) {
                (true, '+') => '-',
                (true, '/') => '_',
                _ => c,
            });
        }
        if !url {
            for _ in chunk.len()..3 {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64 with padding (HTTP Basic).
pub fn base64_std(bytes: &[u8]) -> String {
    base64_with(bytes, false)
}

/// base64url without padding (PKCE, state).
pub fn base64_url(bytes: &[u8]) -> String {
    base64_with(bytes, true)
}

fn decode_b64url(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut n = 0u32;
    let mut out = Vec::new();
    for ch in text.trim_end_matches('=').chars() {
        let v = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '-' | '+' => 62,
            '_' | '/' => 63,
            _ => return None,
        };
        n = (n << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((n >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// A PKCE pair (RFC 7636, S256).
#[derive(Debug, Clone)]
pub struct Pkce {
    /// Keep server-side until the code exchange.
    pub code_verifier: String,
    /// `base64url(sha256(verifier))`.
    pub code_challenge: String,
}

impl Pkce {
    /// A new verifier (64 characters) and its challenge.
    pub fn new() -> Self {
        let mut b = [0u8; 48];
        rand::rng().fill_bytes(&mut b);
        let code_verifier = base64_url(&b);
        Pkce {
            code_challenge: pkce_challenge(&code_verifier),
            code_verifier,
        }
    }
}

impl Default for Pkce {
    fn default() -> Self {
        Self::new()
    }
}

/// S256 challenge of a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    base64_url(&Sha256::digest(verifier.as_bytes()))
}

/// Random URL-safe value for `state` or `nonce`.
pub fn random_state() -> String {
    let mut b = [0u8; 24];
    rand::rng().fill_bytes(&mut b);
    base64_url(&b)
}

/// JWT payload without verification (only for tokens Casdoor just issued).
pub fn payload(token: &str) -> Option<Value> {
    let part = token.split('.').nth(1)?;
    serde_json::from_slice(&decode_b64url(part)?).ok()
}

/// `application/x-www-form-urlencoded` body.
pub fn form_body(pairs: &[(&str, &str)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

/// `VALIDATION` for an empty value (Casdoor would answer "Phone number is invalid").
pub fn required(op: &str, name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::validation(format!("{op}: {name} must not be empty")));
    }
    Ok(())
}

/// OAuth tokens. `Debug` never prints them.
#[derive(Clone)]
pub struct TokenSet {
    /// Access token (JWT).
    pub access_token: String,
    /// Refresh token.
    pub refresh_token: Option<String>,
    /// OpenID Connect id token.
    pub id_token: Option<String>,
    /// Token type (`Bearer`).
    pub token_type: String,
    /// Access token expiry.
    pub expires_at: Option<SystemTime>,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("token_type", &self.token_type)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl TokenSet {
    /// From a token endpoint body.
    pub fn from_body(op: &str, body: &Value, now: SystemTime) -> Result<Self> {
        let s = |k: &str| {
            body.get(k)
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        let access_token = s("access_token")
            .ok_or_else(|| Error::validation(format!("{op}: Casdoor returned no access_token")))?;
        Ok(TokenSet {
            access_token,
            refresh_token: s("refresh_token"),
            id_token: s("id_token"),
            token_type: s("token_type").unwrap_or_else(|| "Bearer".to_owned()),
            expires_at: body
                .get("expires_in")
                .and_then(Value::as_u64)
                .filter(|v| *v > 0)
                .map(|v| now + Duration::from_secs(v)),
        })
    }
}

/// Maps a Casdoor `{"status":"error","msg":…}` envelope (message already redacted).
pub fn envelope_error(op: &str, msg: &str) -> Error {
    let m = msg.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| m.contains(w));
    let (code, hint) = if has(&["phone number is invalid"]) {
        (
            ErrorCode::Validation,
            " (Casdoor sends this for an empty password or code: check that the value was loaded)",
        )
    } else if has(&[
        "remaining chances",
        "password or code is incorrect",
        "please login first",
        "please sign in first",
        "access token",
    ]) {
        (ErrorCode::Authentication, "")
    } else if has(&["too many times", "only send one code", "too frequent"]) {
        (ErrorCode::RateLimited, "")
    } else if has(&[
        "unauthorized operation",
        "forbidden",
        "not allowed",
        "frozen",
        "locked",
    ]) {
        (ErrorCode::PermissionDenied, "")
    } else if has(&["already exist", "duplicate key", "already used"]) {
        (ErrorCode::Conflict, "")
    } else if has(&["not exist", "doesn't exist", "not found", "sign up first"]) {
        (ErrorCode::NotFound, "")
    } else if has(&["is not enabled", "is disabled", "not supported"]) {
        (ErrorCode::Unsupported, "")
    } else {
        (ErrorCode::Validation, "")
    };
    let text = if msg.is_empty() {
        "Casdoor returned status error"
    } else {
        msg
    };
    let mut e = Error::new(code, format!("{op}: {text}{hint}"));
    if code == ErrorCode::RateLimited {
        e = e
            .with_retryable(false)
            .with_retry_after(Duration::from_secs(60));
    }
    e
}

/// Maps an OAuth `{"error","error_description"}` body.
pub fn oauth_error(op: &str, error: &str, description: &str, status: u16) -> Error {
    let text = if description.is_empty() {
        error.to_owned()
    } else {
        format!("{error}: {description}")
    };
    let code = match error {
        _ if description.to_lowercase().contains("mfa enabled") => ErrorCode::Authentication,
        "invalid_grant" | "invalid_client" | "unauthorized_client" => ErrorCode::Authentication,
        "unsupported_grant_type" | "unsupported_response_type" => ErrorCode::Unsupported,
        _ => ErrorCode::Validation,
    };
    Error::new(code, format!("{op}: {text}")).with_status(status)
}

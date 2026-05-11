//! Generic Supabase + JWT auth primitives for Leitner-box study apps.
//!
//! This crate is I/O-free. It builds [`RequestDetails`] structs that the
//! consumer executes with any HTTP client (reqwest, gloo-net, etc.), and
//! exposes pure helpers for parsing Supabase JWT-style access tokens.
//!
//! ## WebAssembly support
//!
//! [`is_jwt_expired`] needs a wall clock. On native targets it uses
//! `std::time::SystemTime`. On `wasm32-unknown-unknown` that returns the
//! Unix epoch (silently), so callers must enable the `wasm` feature to
//! route through `js_sys::Date::now()` instead.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Supabase project configuration.
///
/// Apps construct this with their own project URL and anon key.
#[derive(Debug, Clone)]
pub struct SupabaseConfig {
    pub base_url: String,
    pub anon_key: String,
}

/// Everything needed to make an HTTP request (no async, no HTTP client).
///
/// Built by request-shaping functions in this crate (and by application
/// code for app-specific endpoints), executed by the consumer with their
/// preferred HTTP client. Header names and values are `Cow<'static, str>`
/// so static strings borrow instead of allocating.
#[derive(Debug)]
pub struct RequestDetails {
    pub url: String,
    pub method: String,
    pub headers: Vec<(Cow<'static, str>, Cow<'static, str>)>,
    pub body: Option<String>,
}

/// Authenticated session data shared across frontends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
    #[serde(default)]
    pub email: String,
}

/// Standard Supabase request headers (apikey + Bearer auth).
pub fn common_headers(
    config: &SupabaseConfig,
    access_token: &str,
) -> Vec<(Cow<'static, str>, Cow<'static, str>)> {
    vec![
        (Cow::Borrowed("apikey"), Cow::Owned(config.anon_key.clone())),
        (
            Cow::Borrowed("Authorization"),
            Cow::Owned(format!("Bearer {}", access_token)),
        ),
    ]
}

/// Build a request to refresh an access token using a refresh token.
pub fn refresh_token_request(config: &SupabaseConfig, refresh_token: &str) -> RequestDetails {
    RequestDetails {
        url: format!("{}/auth/v1/token?grant_type=refresh_token", config.base_url),
        method: "POST".to_string(),
        headers: vec![
            (Cow::Borrowed("apikey"), Cow::Owned(config.anon_key.clone())),
            (
                Cow::Borrowed("Content-Type"),
                Cow::Borrowed("application/json"),
            ),
        ],
        body: Some(serde_json::json!({ "refresh_token": refresh_token }).to_string()),
    }
}

/// Parse a token-refresh JSON response into an AuthSession.
///
/// `old_refresh_token` is used as a fallback if the response doesn't
/// include a new one — Supabase doesn't always rotate the refresh token.
pub fn parse_refresh_response(
    json: &serde_json::Value,
    old_refresh_token: &str,
) -> Option<AuthSession> {
    let access_token = json.get("access_token")?.as_str()?.to_string();
    let refresh_token = json
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or(old_refresh_token)
        .to_string();
    let user_id = user_id_from_jwt(&access_token)?;
    let email = email_from_jwt(&access_token).unwrap_or_default();

    Some(AuthSession {
        access_token,
        refresh_token,
        user_id,
        email,
    })
}

/// Decode the JWT payload as a JSON Value.
fn jwt_payload(token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = parts[1];
    let padded = match payload.len() % 4 {
        2 => format!("{}==", payload),
        3 => format!("{}=", payload),
        _ => payload.to_string(),
    };
    let decoded = base64_decode(&padded)?;
    serde_json::from_slice(&decoded).ok()
}

#[cfg(not(target_arch = "wasm32"))]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(target_arch = "wasm32")]
fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Check if a JWT's `exp` claim is in the past (with a 60-second buffer).
///
/// See the crate-level docs for the wasm32 caveat.
pub fn is_jwt_expired(token: &str) -> bool {
    let Some(payload) = jwt_payload(token) else {
        return true;
    };
    let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) else {
        return true;
    };
    now_secs() + 60 >= exp
}

/// Extract the `sub` (user ID) from a JWT without verification.
pub fn user_id_from_jwt(token: &str) -> Option<String> {
    jwt_payload(token)?
        .get("sub")?
        .as_str()
        .map(|s| s.to_string())
}

/// Extract the email from a JWT without verification.
pub fn email_from_jwt(token: &str) -> Option<String> {
    jwt_payload(token)?
        .get("email")?
        .as_str()
        .map(|s| s.to_string())
}

/// Minimal base64 URL-safe decoder (no external crate needed).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let standard: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();

    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;

    for c in standard.bytes() {
        let val = if c == b'=' {
            break;
        } else if let Some(pos) = TABLE.iter().position(|&b| b == c) {
            pos as u32
        } else {
            return None;
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    // All test JWTs use a fake signature — we never verify signatures.
    // Payloads are real base64url-encoded JSON.

    // Payload: {"sub":"12345678-abcd-1234-abcd-123456789abc","role":"authenticated"}
    const JWT_WITH_SUB: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
         .eyJzdWIiOiIxMjM0NTY3OC1hYmNkLTEyMzQtYWJjZC0xMjM0NTY3ODlhYmMiLCJyb2xlIjoiYXV0aGVudGljYXRlZCJ9\
         .fake_signature";

    // Payload: {"sub":"user-abc","email":"test@example.com","exp":9999999999}
    // exp = year 2286 - clearly not expired
    const JWT_NOT_EXPIRED: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
         .eyJzdWIiOiJ1c2VyLWFiYyIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsImV4cCI6OTk5OTk5OTk5OX0\
         .fake_sig";

    // Payload: {"sub":"user-abc","email":"test@example.com","exp":1}
    // exp = 1 (Unix epoch + 1s) - always expired
    const JWT_EXPIRED: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
         .eyJzdWIiOiJ1c2VyLWFiYyIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsImV4cCI6MX0\
         .fake_sig";

    // Payload: {"sub":"user-abc"} — no exp claim
    const JWT_NO_EXP: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
         .eyJzdWIiOiJ1c2VyLWFiYyJ9\
         .fake_sig";

    // --- user_id_from_jwt ---

    #[test]
    fn test_user_id_from_jwt() {
        let uid = user_id_from_jwt(JWT_WITH_SUB);
        assert_eq!(
            uid,
            Some("12345678-abcd-1234-abcd-123456789abc".to_string())
        );
    }

    #[test]
    fn test_user_id_from_invalid_jwt() {
        assert_eq!(user_id_from_jwt("not-a-jwt"), None);
        assert_eq!(user_id_from_jwt(""), None);
    }

    #[test]
    fn user_id_from_jwt_two_parts_only_returns_none() {
        assert_eq!(None, user_id_from_jwt("header.payload"));
    }

    // --- email_from_jwt ---

    #[test]
    fn email_from_jwt_with_email_claim() {
        let email = email_from_jwt(JWT_NOT_EXPIRED);
        assert_eq!(Some("test@example.com".to_string()), email);
    }

    #[test]
    fn email_from_jwt_without_email_claim_returns_none() {
        let email = email_from_jwt(JWT_WITH_SUB);
        assert_eq!(None, email);
    }

    #[test]
    fn email_from_jwt_invalid_token_returns_none() {
        assert_eq!(None, email_from_jwt("not.a.token"));
    }

    // --- is_jwt_expired ---

    #[test]
    fn is_jwt_expired_far_future_exp_returns_false() {
        assert!(!is_jwt_expired(JWT_NOT_EXPIRED));
    }

    #[test]
    fn is_jwt_expired_past_exp_returns_true() {
        assert!(is_jwt_expired(JWT_EXPIRED));
    }

    #[test]
    fn is_jwt_expired_no_exp_claim_returns_true() {
        assert!(is_jwt_expired(JWT_NO_EXP));
    }

    #[test]
    fn is_jwt_expired_malformed_token_returns_true() {
        assert!(is_jwt_expired("not-a-token"));
        assert!(is_jwt_expired(""));
        assert!(is_jwt_expired("only.two-parts"));
    }

    #[test]
    fn is_jwt_expired_invalid_base64_payload_returns_true() {
        assert!(is_jwt_expired("header.!!!invalid!!!.sig"));
    }

    // --- parse_refresh_response ---

    #[test]
    fn parse_refresh_response_with_all_fields() {
        let json = serde_json::json!({
            "access_token": JWT_NOT_EXPIRED,
            "refresh_token": "new_refresh_token_xyz",
        });
        let session = parse_refresh_response(&json, "old_refresh_token").unwrap();
        assert_eq!(JWT_NOT_EXPIRED, session.access_token);
        assert_eq!("new_refresh_token_xyz", session.refresh_token);
        assert_eq!("user-abc", session.user_id);
        assert_eq!("test@example.com", session.email);
    }

    #[test]
    fn parse_refresh_response_falls_back_to_old_refresh_token_when_missing() {
        let json = serde_json::json!({
            "access_token": JWT_NOT_EXPIRED,
        });
        let session = parse_refresh_response(&json, "old_refresh_token").unwrap();
        assert_eq!("old_refresh_token", session.refresh_token);
    }

    #[test]
    fn parse_refresh_response_missing_access_token_returns_none() {
        let json = serde_json::json!({
            "refresh_token": "some_refresh",
        });
        assert!(parse_refresh_response(&json, "old").is_none());
    }

    #[test]
    fn parse_refresh_response_invalid_access_token_no_sub_returns_none() {
        let json = serde_json::json!({
            "access_token": "header.payload.sig",
            "refresh_token": "some_refresh",
        });
        assert!(parse_refresh_response(&json, "old").is_none());
    }

    #[test]
    fn parse_refresh_response_empty_json_returns_none() {
        let json = serde_json::json!({});
        assert!(parse_refresh_response(&json, "old").is_none());
    }

    // --- request builders ---

    #[test]
    fn refresh_token_request_uses_correct_url_and_body() {
        let config = SupabaseConfig {
            base_url: "https://example.supabase.co".to_string(),
            anon_key: "anon-key-xyz".to_string(),
        };
        let req = refresh_token_request(&config, "refresh-abc");
        assert_eq!(
            req.url,
            "https://example.supabase.co/auth/v1/token?grant_type=refresh_token"
        );
        assert_eq!(req.method, "POST");
        assert_eq!(
            req.body.as_deref(),
            Some(r#"{"refresh_token":"refresh-abc"}"#)
        );
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k.as_ref() == "apikey" && v.as_ref() == "anon-key-xyz")
        );
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k.as_ref() == "Content-Type" && v.as_ref() == "application/json")
        );
    }

    /// Refresh tokens that contain JSON-special characters must be safely escaped.
    #[test]
    fn refresh_token_request_escapes_special_characters_in_body() {
        let config = SupabaseConfig {
            base_url: "https://example.supabase.co".to_string(),
            anon_key: "k".to_string(),
        };
        let req = refresh_token_request(&config, r#"tok"with\quotes"#);
        // Parse the body back as JSON and verify the round-trip
        let body = req.body.expect("body");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            parsed.get("refresh_token").and_then(|v| v.as_str()),
            Some(r#"tok"with\quotes"#)
        );
    }

    #[test]
    fn common_headers_includes_apikey_and_bearer() {
        let config = SupabaseConfig {
            base_url: "https://example.supabase.co".to_string(),
            anon_key: "anon-key".to_string(),
        };
        let headers = common_headers(&config, "access-token-123");
        assert!(
            headers
                .iter()
                .any(|(k, v)| k.as_ref() == "apikey" && v.as_ref() == "anon-key")
        );
        assert!(
            headers
                .iter()
                .any(|(k, v)| k.as_ref() == "Authorization"
                    && v.as_ref() == "Bearer access-token-123")
        );
    }

    /// The 60s "treat-as-expired" buffer should fire for JWTs that expire imminently.
    #[test]
    fn is_jwt_expired_within_buffer_returns_true() {
        // Build a JWT whose exp is now + 30s — should be treated as expired.
        let exp = now_secs() + 30;
        let payload = format!(r#"{{"sub":"u","exp":{}}}"#, exp);
        let payload_b64 = base64_url_encode(payload.as_bytes());
        let token = format!("header.{}.sig", payload_b64);
        assert!(is_jwt_expired(&token));
    }

    /// Helper for the buffer test: encode bytes as URL-safe base64 without padding.
    fn base64_url_encode(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for &b in input {
            buf = (buf << 8) | b as u32;
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                output.push(TABLE[((buf >> bits) & 0x3F) as usize] as char);
            }
        }
        if bits > 0 {
            output.push(TABLE[((buf << (6 - bits)) & 0x3F) as usize] as char);
        }
        output
    }
}

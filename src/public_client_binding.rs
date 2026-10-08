//! Proof-of-possession binding for password-derived public capabilities.
//!
//! Network identity remains useful for throttling and audit, but cannot
//! distinguish two browsers behind one NAT. Public grants and upload sessions
//! therefore bind to a separate random client secret carried either by an
//! HttpOnly browser cookie or an explicit native-client header.

use axum::http::{header, HeaderMap, HeaderValue};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    auth::random_secret_token,
    error::{ApiError, ApiResult},
    server::AppState,
};

const HOST_COOKIE_NAME: &str = "__Host-shellx_drive_public_client";
const DEVELOPMENT_COOKIE_NAME: &str = "shellx_drive_public_client_dev";
const CLIENT_SECRET_HEADER: &str = "x-shellx-public-client-secret";
const SECRET_BYTES_HEX: usize = 64;
const COOKIE_MAX_AGE_SECONDS: u64 = 86_400;
type HmacSha256 = Hmac<Sha256>;

pub(crate) struct PublicClientBinding {
    fingerprint: String,
    set_cookie: Option<HeaderValue>,
}

impl PublicClientBinding {
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn apply_cookie(&self, headers: &mut HeaderMap) {
        if let Some(cookie) = self.set_cookie.clone() {
            headers.append(header::SET_COOKIE, cookie);
        }
    }
}

/// Return a binding for a capability-minting response. Browsers without a
/// cookie receive a fresh HttpOnly secret; native clients may supply their own
/// 32-byte random hexadecimal secret in the explicit header.
pub(crate) fn provision(state: &AppState, headers: &HeaderMap) -> ApiResult<PublicClientBinding> {
    if let Some(secret) = explicit_secret(headers)? {
        return Ok(PublicClientBinding {
            fingerprint: fingerprint(secret, &state.config.token)?,
            set_cookie: None,
        });
    }
    let cookie_name = cookie_name(state);
    if let Some(secret) = cookie_secret(headers, cookie_name)? {
        return Ok(PublicClientBinding {
            fingerprint: fingerprint(secret, &state.config.token)?,
            set_cookie: None,
        });
    }
    let secret = random_secret_token();
    let mut cookie = format!(
        "{cookie_name}={secret}; Path=/; Max-Age={COOKIE_MAX_AGE_SECONDS}; HttpOnly; SameSite=Strict"
    );
    if state.config.secure_cookies {
        cookie.push_str("; Secure");
    }
    let set_cookie = HeaderValue::from_str(&cookie)
        .map_err(|_| ApiError::Maintenance("could not create public client cookie".to_string()))?;
    Ok(PublicClientBinding {
        fingerprint: fingerprint(&secret, &state.config.token)?,
        set_cookie: Some(set_cookie),
    })
}

/// Require the same client-held proof used when the capability was minted.
pub(crate) fn require(state: &AppState, headers: &HeaderMap) -> ApiResult<String> {
    from_request(state, headers)?.ok_or(ApiError::Unauthenticated)
}

pub(crate) fn require_binding(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<PublicClientBinding> {
    Ok(PublicClientBinding {
        fingerprint: require(state, headers)?,
        set_cookie: None,
    })
}

pub(crate) fn from_request(state: &AppState, headers: &HeaderMap) -> ApiResult<Option<String>> {
    let secret = match explicit_secret(headers)? {
        Some(secret) => Some(secret),
        None => cookie_secret(headers, cookie_name(state))?,
    };
    secret
        .map(|secret| fingerprint(secret, &state.config.token))
        .transpose()
}

fn cookie_name(state: &AppState) -> &'static str {
    if state.config.secure_cookies {
        HOST_COOKIE_NAME
    } else {
        DEVELOPMENT_COOKIE_NAME
    }
}

fn explicit_secret(headers: &HeaderMap) -> ApiResult<Option<&str>> {
    let Some(value) = headers.get(CLIENT_SECRET_HEADER) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| ApiError::Validation("public client secret header is invalid".to_string()))?;
    if !valid_secret(value) {
        return Err(ApiError::Validation(
            "public client secret must be 32 random bytes encoded as hexadecimal".to_string(),
        ));
    }
    Ok(Some(value))
}

fn cookie_secret<'a>(headers: &'a HeaderMap, cookie_name: &str) -> ApiResult<Option<&'a str>> {
    let mut matches = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter_map(|(name, value)| (name == cookie_name).then_some(value));
    let Some(secret) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(ApiError::Validation(
            "public client proof cookie is duplicated".to_string(),
        ));
    }
    if !valid_secret(secret) {
        return Err(ApiError::Validation(
            "public client proof cookie is invalid".to_string(),
        ));
    }
    Ok(Some(secret))
}

fn valid_secret(value: &str) -> bool {
    value.len() == SECRET_BYTES_HEX && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn fingerprint(secret: &str, signing_key: &str) -> ApiResult<String> {
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .map_err(|_| ApiError::Maintenance("public client binding key is invalid".to_string()))?;
    mac.update(b"shellx-drive-public-client-v1\0");
    mac.update(secret.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests;

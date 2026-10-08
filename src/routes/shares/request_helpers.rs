use axum::http::{header, HeaderMap};
use chrono::{DateTime, Utc};

use super::ShareAccessQuery;

const SHARE_PASSWORD_HEADER: &str = "x-share-password";
const SHARE_ACCESS_TOKEN_HEADER: &str = "x-share-access-token";

/// Content negotiation for `GET /pub/shares/{id}`: JSON when `?format=json` or
/// the `Accept` header names `application/json`; HTML otherwise.
pub(super) fn wants_json(headers: &HeaderMap, query: &ShareAccessQuery) -> bool {
    if query.format.as_deref() == Some("json") {
        return true;
    }
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|accept| accept.contains("application/json"))
        .unwrap_or(false)
}

/// Whether a share's stored expiry has passed. `None` = never expires (a
/// permanent link) -> always valid. A present-but-unparseable timestamp is
/// treated as expired (fail-closed).
pub(super) fn is_expired(expires_at: Option<&str>) -> bool {
    match expires_at {
        None => false,
        Some(value) => DateTime::parse_from_rfc3339(value)
            .map(|dt| dt.with_timezone(&Utc) < Utc::now())
            .unwrap_or(true),
    }
}

pub(super) fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The link password supplied by the caller. Absence or malformed header bytes
/// are not equivalent to an explicitly supplied empty legacy password.
pub(super) fn share_password_from_request(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(SHARE_PASSWORD_HEADER)
        .and_then(|value| value.to_str().ok())
}

pub(super) fn share_access_token_from_request(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(SHARE_ACCESS_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Whether the caller supplied a link password header — used by the metadata
/// endpoint to decide whether to verify a protected folder before listing it.
pub(super) fn share_password_supplied(headers: &HeaderMap) -> bool {
    headers.contains_key(SHARE_PASSWORD_HEADER)
}

use std::collections::HashSet;

use axum::http::HeaderMap;

use crate::{
    error::{ApiError, ApiResult},
    storage::{WebDavLockDepth, MAX_WEBDAV_LOCK_TIMEOUT_SECONDS},
};

use super::{DEFAULT_LOCK_TIMEOUT_SECONDS, MAX_LOCK_BODY_BYTES};

pub(super) fn requested_lock_depth(headers: &HeaderMap) -> ApiResult<WebDavLockDepth> {
    match headers
        .get("Depth")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        None | Some("infinity") => Ok(WebDavLockDepth::Infinity),
        Some("0") => Ok(WebDavLockDepth::Zero),
        _ => Err(ApiError::Validation(
            "LOCK Depth must be 0 or infinity".to_string(),
        )),
    }
}

pub(super) fn requested_timeout(headers: &HeaderMap) -> ApiResult<i64> {
    let Some(raw) = headers.get("Timeout") else {
        return Ok(DEFAULT_LOCK_TIMEOUT_SECONDS);
    };
    let raw = raw
        .to_str()
        .map_err(|_| ApiError::Validation("invalid Timeout header".to_string()))?;
    for candidate in raw.split(',').map(str::trim) {
        if candidate.eq_ignore_ascii_case("infinite") {
            return Ok(MAX_WEBDAV_LOCK_TIMEOUT_SECONDS);
        }
        if let Some(seconds) = candidate
            .to_ascii_lowercase()
            .strip_prefix("second-")
            .and_then(|value| value.parse::<i64>().ok())
        {
            return Ok(seconds.clamp(1, MAX_WEBDAV_LOCK_TIMEOUT_SECONDS));
        }
    }
    Err(ApiError::Validation(
        "Timeout must contain Infinite or Second-N".to_string(),
    ))
}

pub(super) fn validate_lock_body(body: &[u8]) -> ApiResult<()> {
    if body.len() > MAX_LOCK_BODY_BYTES {
        return Err(ApiError::PayloadTooLarge(
            "WebDAV LOCK body exceeds 16 KiB".to_string(),
        ));
    }
    let body = std::str::from_utf8(body)
        .map_err(|_| ApiError::Validation("LOCK body must be UTF-8 XML".to_string()))?;
    if has_local_element(body, "shared") {
        return Err(ApiError::NotImplemented(
            "shared WebDAV locks are not supported; use exclusive write locks".to_string(),
        ));
    }
    if !has_local_element(body, "lockinfo")
        || !has_local_element(body, "exclusive")
        || !has_local_element(body, "write")
    {
        return Err(ApiError::Validation(
            "LOCK body must request an exclusive write lock".to_string(),
        ));
    }
    Ok(())
}

fn has_local_element(xml: &str, expected: &str) -> bool {
    let bytes = xml.as_bytes();
    let mut offset = 0;
    while let Some(relative) = xml[offset..].find('<') {
        let start = offset + relative + 1;
        let rest = &xml[start..];
        let rest = rest.trim_start_matches(['/', '?', '!']).trim_start();
        let name = rest
            .split(|ch: char| ch.is_whitespace() || matches!(ch, '>' | '/'))
            .next()
            .unwrap_or("")
            .rsplit(':')
            .next()
            .unwrap_or("");
        if name.eq_ignore_ascii_case(expected) {
            return true;
        }
        offset = start.min(bytes.len());
    }
    false
}

pub(super) fn submitted_tokens(headers: &HeaderMap) -> ApiResult<HashSet<String>> {
    let Some(raw) = headers.get("If") else {
        return Ok(HashSet::new());
    };
    let raw = raw
        .to_str()
        .map_err(|_| ApiError::Validation("invalid If header".to_string()))?;
    let mut tokens = HashSet::new();
    let mut remaining = raw;
    while let Some(start) = remaining.find('<') {
        remaining = &remaining[start + 1..];
        let Some(end) = remaining.find('>') else {
            return Err(ApiError::Validation("malformed If header".to_string()));
        };
        let candidate = remaining[..end].trim();
        if candidate.starts_with("opaquelocktoken:") {
            tokens.insert(candidate.to_string());
        }
        remaining = &remaining[end + 1..];
    }
    Ok(tokens)
}

pub(super) fn coded_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let value = trimmed.strip_prefix('<')?.strip_suffix('>')?.trim();
    if value.starts_with("opaquelocktoken:") {
        Some(value.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_namespaced_lockinfo_and_if_tokens() {
        let body = br#"<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#;
        validate_lock_body(body).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "If",
            "(<opaquelocktoken:one>) (<opaquelocktoken:two>)"
                .parse()
                .unwrap(),
        );
        let tokens = submitted_tokens(&headers).unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(tokens.contains("opaquelocktoken:one"));
    }

    #[test]
    fn rejects_shared_lock_scope_honestly() {
        let body = br#"<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:shared/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>"#;
        assert!(matches!(
            validate_lock_body(body),
            Err(ApiError::NotImplemented(_))
        ));
    }
}

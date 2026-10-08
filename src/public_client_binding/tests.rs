use super::*;

#[test]
fn cookie_parser_accepts_only_the_exact_host_cookie_secret() {
    let secret = "ab".repeat(32);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("other=x; {HOST_COOKIE_NAME}={secret}")).unwrap(),
    );
    assert_eq!(
        cookie_secret(&headers, HOST_COOKIE_NAME).unwrap(),
        Some(secret.as_str())
    );
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("shellx_drive_public_client=short"),
    );
    assert_eq!(cookie_secret(&headers, HOST_COOKIE_NAME).unwrap(), None);
}

#[test]
fn cookie_parser_rejects_duplicate_or_invalid_proof_cookies() {
    let secret = "ab".repeat(32);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!(
            "{HOST_COOKIE_NAME}={secret}; {HOST_COOKIE_NAME}={secret}"
        ))
        .unwrap(),
    );
    assert!(cookie_secret(&headers, HOST_COOKIE_NAME).is_err());

    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("__Host-shellx_drive_public_client=short"),
    );
    assert!(cookie_secret(&headers, HOST_COOKIE_NAME).is_err());
}

#[test]
fn production_and_development_cookie_names_are_distinct() {
    let secret = "ab".repeat(32);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("{DEVELOPMENT_COOKIE_NAME}={secret}")).unwrap(),
    );
    assert_eq!(cookie_secret(&headers, HOST_COOKIE_NAME).unwrap(), None);
    assert_eq!(
        cookie_secret(&headers, DEVELOPMENT_COOKIE_NAME).unwrap(),
        Some(secret.as_str())
    );
}

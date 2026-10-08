use axum::{
    body::to_bytes,
    http::{header, HeaderValue, StatusCode},
};

use crate::{
    config::{Config, PublicOrigin},
    error::ApiError,
};

use super::*;

fn test_state(data_dir: std::path::PathBuf) -> AppState {
    AppState::open(Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir,
        token: "test-token".to_string(),
        bootstrap_token: None,
        e2e_enabled: true,
        email_transport: "capture".to_string(),
        email_from: "ShellX Drive <noreply@example.test>".to_string(),
        public_origin: PublicOrigin::parse("http://127.0.0.1").unwrap(),
        email_smtp_host_source: "not_configured".to_string(),
        email_smtp_port: None,
        email_smtp_user_source: "not_configured".to_string(),
        maintenance_token_source: "not_configured".to_string(),
        maintenance_sudo_source: "not_configured".to_string(),
        local_session_ttl_seconds: 2_592_000,
        office_provider_name: "Office editor".to_string(),
        office_provider_url: None,
        office_session_ttl_seconds: 900,
        hosted_mode: false,
        hosted_billing_provider: "none".to_string(),
        hosted_public_rate_limit_per_minute: 60,
        backup_max_archive_bytes: 9 * 1024 * 1024 * 1024 * 1024,
        secure_cookies: false,
        trust_proxy_headers: false,
        update_repo: None,
    })
    .unwrap()
}

#[test]
fn multistatus_counts_the_xml_wrapper_in_its_byte_limit() {
    assert!(matches!(
        multistatus("x".repeat(16 * 1024 * 1024)),
        Err(ApiError::PayloadTooLarge(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn propfind_unread_body_releases_both_admission_lanes_on_deadline() {
    let data = tempfile::tempdir().unwrap();
    let state = test_state(data.path().to_path_buf());
    let (workspace, _, _) = state
        .storage
        .create_workspace("DAV", "owner@example.test")
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer test-token"),
    );
    let partition = format!("webdav:system@local:{}", workspace.id);

    let unread = propfind(
        state.clone(),
        headers.clone(),
        workspace.id.clone(),
        String::new(),
    )
    .await
    .unwrap();
    assert_eq!(unread.status(), StatusCode::MULTI_STATUS);
    assert_eq!(
        unread.headers()[header::CONTENT_TYPE],
        "application/xml; charset=utf-8"
    );
    let _second = state.try_metadata_planning(&partition).unwrap();
    assert!(matches!(
        state.try_metadata_planning(&partition),
        Err(ApiError::TooManyRequests)
    ));
    let mut body_permits = Vec::new();
    for _ in 0..15 {
        body_permits.push(state.try_authenticated_body_stream("system@local").unwrap());
    }
    assert!(matches!(
        state.try_authenticated_body_stream("system@local"),
        Err(ApiError::TooManyRequests)
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(10 * 60 + 1)).await;
    tokio::task::yield_now().await;
    assert!(state.try_metadata_planning(&partition).is_ok());
    assert!(state.try_authenticated_body_stream("system@local").is_ok());
    drop(unread);
    drop(body_permits);

    let delivered = propfind(state, headers, workspace.id, String::new())
        .await
        .unwrap();
    let expected_len: usize = delivered.headers()[header::CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let xml = to_bytes(delivered.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(xml.len(), expected_len);
    assert!(xml.starts_with(b"<?xml version=\"1.0\""));
    assert!(xml.ends_with(b"</d:multistatus>"));
}

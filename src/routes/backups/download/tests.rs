use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue},
};

use super::download_backup;
use crate::{auth::ADMIN_ACTOR, config::Config, error::ApiError, server::AppState};

fn test_state(data_dir: std::path::PathBuf) -> AppState {
    AppState::open(Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir,
        token: "test-token".to_string(),
        bootstrap_token: None,
        e2e_enabled: true,
        email_transport: "capture".to_string(),
        email_from: "ShellX Drive <noreply@example.test>".to_string(),
        public_origin: crate::config::PublicOrigin::parse("http://127.0.0.1").unwrap(),
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

fn operator_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer test-token"),
    );
    headers
}

fn unmanaged_v2_fixture(state: &AppState, backup_id: &str) {
    let backups = state.data_dir().join("backups");
    std::fs::create_dir_all(&backups).unwrap();
    std::fs::write(backups.join(format!("{backup_id}.sxdbackup")), b"fixture").unwrap();
}

#[tokio::test]
async fn saturated_backup_work_rejects_v2_before_metadata_or_snapshot_allocation() {
    let data = tempfile::tempdir().unwrap();
    let state = test_state(data.path().to_path_buf());
    let backup_id = "v2-backup-work-admission";
    unmanaged_v2_fixture(&state, backup_id);
    let _held = state.try_backup_work().unwrap();

    let error = download_backup(
        State(state),
        operator_headers(),
        Path(backup_id.to_string()),
    )
    .await
    .unwrap_err();

    assert!(matches!(error, ApiError::TooManyRequests));
    assert!(!data.path().join(".backup-download-snapshots").exists());
}

#[tokio::test]
async fn saturated_body_streams_reject_v2_before_snapshot_allocation() {
    let data = tempfile::tempdir().unwrap();
    let state = test_state(data.path().to_path_buf());
    let backup_id = "v2-body-stream-admission";
    unmanaged_v2_fixture(&state, backup_id);
    let mut held = Vec::new();
    loop {
        match state.try_authenticated_body_stream(ADMIN_ACTOR) {
            Ok(permit) => held.push(permit),
            Err(ApiError::TooManyRequests) => break,
            Err(error) => panic!("unexpected body-stream admission error: {error}"),
        }
    }
    assert!(!held.is_empty());

    let error = download_backup(
        State(state.clone()),
        operator_headers(),
        Path(backup_id.to_string()),
    )
    .await
    .unwrap_err();

    assert!(matches!(error, ApiError::TooManyRequests));
    assert!(!data.path().join(".backup-download-snapshots").exists());
    state.try_backup_work().unwrap();
}

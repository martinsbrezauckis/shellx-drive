use std::time::Duration;

use super::AppState;
use crate::config::Config;

#[tokio::test]
async fn detached_mutation_retains_restore_drain_after_request_waiter_is_aborted() {
    let temp = tempfile::tempdir().unwrap();
    let state = AppState::open(test_config(temp.path().to_path_buf())).unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mutation_state = state.clone();
    let request_waiter = tokio::spawn(async move {
        mutation_state
            .run_detached_mutation(async move {
                let _ = entered_tx.send(());
                let _ = release_rx.await;
                Ok::<_, crate::error::ApiError>(())
            })
            .await
    });
    entered_rx.await.unwrap();
    request_waiter.abort();

    let restore_state = state.clone();
    let mut restore = tokio::spawn(async move {
        restore_state
            .begin_legacy_backup_restore("detached-mutation-test")
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut restore)
            .await
            .is_err()
    );

    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), &mut restore)
        .await
        .expect("restore writer remained blocked")
        .unwrap()
        .unwrap();
    state.end_backup_restore("detached-mutation-test");
}

fn test_config(data_dir: std::path::PathBuf) -> Config {
    Config {
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
    }
}

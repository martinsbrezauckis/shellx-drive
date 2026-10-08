use std::{
    fs,
    path::{Path, PathBuf},
};

use super::super::catalog::{
    apply_v2_retention, create_v2_incomplete_marker, hash_file_streaming, v2_backup_path,
    v2_incomplete_marker_present, v2_sidecar_partial_path, v2_sidecar_path, write_v2_sidecar,
    V2SidecarPayload,
};
use super::{recover_backup_state, V2CreatePublicationGuard, SCHEDULED_BACKUP_ACTOR};
use crate::{
    backup_v2,
    config::Config,
    fs_private,
    model::{BackupMetadata, UpdateBackupPolicyRequest},
    server::AppState,
};

mod archive_binding;
mod retention;

fn test_state(data_dir: PathBuf) -> AppState {
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

fn write_test_v2_generation(data_dir: &Path, backup_id: &str, created_at: &str) -> PathBuf {
    let archive = v2_backup_path(data_dir, backup_id).unwrap();
    let content = format!("fixture archive {backup_id}");
    fs_private::write_file_private(&archive, content.as_bytes()).unwrap();
    let archive_bytes = fs::metadata(&archive).unwrap().len();
    let archive_sha256 = hash_file_streaming(&archive, 1024).unwrap();
    write_v2_sidecar(
        data_dir,
        V2SidecarPayload {
            metadata: BackupMetadata {
                backup_id: backup_id.to_string(),
                format: backup_v2::FORMAT.to_string(),
                created_at: created_at.to_string(),
                table_count: 1,
                row_count: 1,
                blob_count: 0,
                content_bytes: archive_bytes,
                archive_bytes: Some(archive_bytes),
                job_id: Some(format!("job-{backup_id}")),
                status: Some("succeeded".to_string()),
                phase: Some("complete".to_string()),
                last_error: None,
            },
            archive_sha256,
        },
    )
    .unwrap();
    archive
}

fn validation_job_count(state: &AppState, backup_id: &str) -> usize {
    state
        .storage
        .list_backup_jobs()
        .unwrap()
        .iter()
        .filter(|job| job.kind == "validate" && job.backup_id == backup_id)
        .count()
}

#[test]
fn startup_recovery_hides_and_cleans_an_interrupted_create_publication() {
    let data_dir = tempfile::tempdir().unwrap();
    let state = test_state(data_dir.path().to_path_buf());
    let backup_id = "interrupted-create";
    let job = state
        .storage
        .enqueue_scheduled_backup_job("create", backup_id, "system@local")
        .unwrap();
    state.storage.claim_backup_job(&job.id).unwrap().unwrap();

    create_v2_incomplete_marker(data_dir.path(), backup_id).unwrap();
    let archive = v2_backup_path(data_dir.path(), backup_id).unwrap();
    let sidecar = v2_sidecar_path(data_dir.path(), backup_id).unwrap();
    let partial = v2_sidecar_partial_path(data_dir.path(), backup_id).unwrap();
    fs_private::write_file_private(&archive, b"complete-but-unpublished").unwrap();
    fs_private::write_file_private(&sidecar, b"unpublished-sidecar").unwrap();
    fs_private::write_file_private(&partial, b"partial-sidecar").unwrap();

    recover_backup_state(&state).unwrap();

    let recovered = state.storage.get_backup_job(&job.id).unwrap().unwrap();
    assert_eq!(recovered.status, "interrupted");
    assert!(!archive.exists());
    assert!(!sidecar.exists());
    assert!(!partial.exists());
    assert!(!v2_incomplete_marker_present(data_dir.path(), backup_id).unwrap());
}

#[test]
fn startup_recovery_keeps_marker_when_failed_create_cleanup_is_incomplete() {
    let data_dir = tempfile::tempdir().unwrap();
    let state = test_state(data_dir.path().to_path_buf());
    let backup_id = "failed-cleanup";
    let job = state
        .storage
        .enqueue_scheduled_backup_job("create", backup_id, "system@local")
        .unwrap();
    let running = state.storage.claim_backup_job(&job.id).unwrap().unwrap();
    state
        .storage
        .finish_backup_job(
            &running.id,
            "failed",
            "failed",
            None,
            Some("fixture create failure"),
        )
        .unwrap();

    create_v2_incomplete_marker(data_dir.path(), backup_id).unwrap();
    let archive = v2_backup_path(data_dir.path(), backup_id).unwrap();
    fs_private::create_dir_all_private(&archive).unwrap();

    recover_backup_state(&state).unwrap();

    let recovered = state.storage.get_backup_job(&job.id).unwrap().unwrap();
    assert_eq!(recovered.status, "failed");
    assert!(archive.is_dir());
    assert!(v2_incomplete_marker_present(data_dir.path(), backup_id).unwrap());
}

#[test]
fn startup_recovery_publishes_a_succeeded_create_without_cleanup() {
    let data_dir = tempfile::tempdir().unwrap();
    let state = test_state(data_dir.path().to_path_buf());
    let backup_id = "succeeded-publication";
    let job = state
        .storage
        .enqueue_scheduled_backup_job("create", backup_id, "system@local")
        .unwrap();
    let running = state.storage.claim_backup_job(&job.id).unwrap().unwrap();
    state
        .storage
        .finish_backup_job(&running.id, "succeeded", "complete", None, None)
        .unwrap();

    create_v2_incomplete_marker(data_dir.path(), backup_id).unwrap();
    let archive = v2_backup_path(data_dir.path(), backup_id).unwrap();
    let sidecar = v2_sidecar_path(data_dir.path(), backup_id).unwrap();
    fs_private::write_file_private(&archive, b"completed archive").unwrap();
    fs_private::write_file_private(&sidecar, b"completed sidecar").unwrap();

    recover_backup_state(&state).unwrap();

    assert!(archive.exists());
    assert!(sidecar.exists());
    assert!(!v2_incomplete_marker_present(data_dir.path(), backup_id).unwrap());
}

#[test]
fn startup_recovery_retries_retention_after_succeeded_marker_was_already_cleared() {
    let data_dir = tempfile::tempdir().unwrap();
    let state = test_state(data_dir.path().to_path_buf());
    state
        .storage
        .update_backup_policy(
            UpdateBackupPolicyRequest {
                enabled: None,
                schedule: None,
                retention_count: Some(1),
            },
            "system@local",
        )
        .unwrap();

    let old_backup_id = "retention-old";
    let published_backup_id = "retention-published";
    let old_archive =
        write_test_v2_generation(data_dir.path(), old_backup_id, "2026-01-01T00:00:00Z");
    let published_archive =
        write_test_v2_generation(data_dir.path(), published_backup_id, "2026-01-02T00:00:00Z");
    let job = state
        .storage
        .enqueue_scheduled_backup_job("create", published_backup_id, "system@local")
        .unwrap();
    let running = state.storage.claim_backup_job(&job.id).unwrap().unwrap();
    state
        .storage
        .finish_backup_job(&running.id, "succeeded", "complete", None, None)
        .unwrap();
    assert!(!v2_incomplete_marker_present(data_dir.path(), published_backup_id).unwrap());

    recover_backup_state(&state).unwrap();

    assert!(!old_archive.exists());
    assert!(published_archive.exists());
}

#[test]
fn zero_retention_fails_before_any_backup_is_deleted() {
    let data_dir = tempfile::tempdir().unwrap();
    let state = test_state(data_dir.path().to_path_buf());
    let first = write_test_v2_generation(
        data_dir.path(),
        "zero-retention-first",
        "2026-01-01T00:00:00Z",
    );
    let second = write_test_v2_generation(
        data_dir.path(),
        "zero-retention-second",
        "2026-01-02T00:00:00Z",
    );
    rusqlite::Connection::open(data_dir.path().join("drive.db"))
        .unwrap()
        .execute(
            "INSERT INTO backup_policy (id, enabled, schedule, retention_count, updated_at)
             VALUES ('default', 1, 'daily', 0, '2026-08-26T00:00:00Z')
             ON CONFLICT(id) DO UPDATE SET retention_count = 0",
            [],
        )
        .unwrap();

    assert!(apply_v2_retention(&state).is_err());
    assert!(first.exists());
    assert!(second.exists());
}

#[test]
fn scheduled_create_enqueues_one_validation_only_after_publication() {
    let data_dir = tempfile::tempdir().unwrap();
    let state = test_state(data_dir.path().to_path_buf());
    let published_backup_id = "scheduled-published";
    let published = state
        .storage
        .enqueue_scheduled_backup_job("create", published_backup_id, SCHEDULED_BACKUP_ACTOR)
        .unwrap();
    let running = state
        .storage
        .claim_backup_job(&published.id)
        .unwrap()
        .unwrap();
    create_v2_incomplete_marker(data_dir.path(), published_backup_id).unwrap();
    assert_eq!(validation_job_count(&state, published_backup_id), 0);
    state
        .storage
        .finish_backup_job(&running.id, "succeeded", "complete", None, None)
        .unwrap();
    assert_eq!(validation_job_count(&state, published_backup_id), 0);

    recover_backup_state(&state).unwrap();
    assert_eq!(validation_job_count(&state, published_backup_id), 1);
    recover_backup_state(&state).unwrap();
    assert_eq!(validation_job_count(&state, published_backup_id), 1);

    let failed_backup_id = "scheduled-failed";
    let failed = state
        .storage
        .enqueue_scheduled_backup_job("create", failed_backup_id, SCHEDULED_BACKUP_ACTOR)
        .unwrap();
    let running = state.storage.claim_backup_job(&failed.id).unwrap().unwrap();
    state
        .storage
        .finish_backup_job(
            &running.id,
            "failed",
            "failed",
            None,
            Some("fixture failure"),
        )
        .unwrap();
    create_v2_incomplete_marker(data_dir.path(), failed_backup_id).unwrap();
    let archive = v2_backup_path(data_dir.path(), failed_backup_id).unwrap();
    fs_private::write_file_private(&archive, b"failed archive").unwrap();

    recover_backup_state(&state).unwrap();

    assert_eq!(validation_job_count(&state, failed_backup_id), 0);
    assert!(!archive.exists());
}

#[test]
fn failed_create_cleanup_preserves_a_previous_completed_generation() {
    let data_dir = tempfile::tempdir().unwrap();
    let old_backup_id = "previous-completed";
    let new_backup_id = "unpublished-generation";
    let old_archive = v2_backup_path(data_dir.path(), old_backup_id).unwrap();
    let old_sidecar = v2_sidecar_path(data_dir.path(), old_backup_id).unwrap();
    fs_private::write_file_private(&old_archive, b"previous archive").unwrap();
    fs_private::write_file_private(&old_sidecar, b"previous sidecar").unwrap();

    let publication = V2CreatePublicationGuard::begin(data_dir.path(), new_backup_id).unwrap();
    let new_archive = v2_backup_path(data_dir.path(), new_backup_id).unwrap();
    let new_sidecar = v2_sidecar_path(data_dir.path(), new_backup_id).unwrap();
    fs_private::write_file_private(&new_archive, b"unpublished archive").unwrap();
    fs_private::write_file_private(&new_sidecar, b"unpublished sidecar").unwrap();

    drop(publication);

    assert!(old_archive.exists());
    assert!(old_sidecar.exists());
    assert!(!new_archive.exists());
    assert!(!new_sidecar.exists());
    assert!(!v2_incomplete_marker_present(data_dir.path(), new_backup_id).unwrap());
}

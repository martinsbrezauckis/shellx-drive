use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::Utc;

use super::*;
use crate::{
    config::Config,
    model::{CreateFileRequest, FileKind},
    routes::backups::spawn_backup_worker,
    server::AppState,
};

pub(super) fn test_state(data_dir: PathBuf) -> AppState {
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

pub(super) fn create_file_with_blob(
    storage: &Storage,
    data_dir: &Path,
    name: &str,
    body: &[u8],
) -> (String, String) {
    let (workspace, _, _) = storage
        .create_workspace(&format!("{name} workspace"), "owner@example.test")
        .unwrap();
    let hash = blob::put_blob(data_dir, body).unwrap();
    let (file, _) = storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: None,
                name: name.to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some(hash.clone()),
            i64::try_from(body.len()).unwrap(),
        )
        .unwrap();
    (file.id, hash)
}

#[tokio::test]
async fn v2_restore_fault_after_deletes_rolls_back_and_cleans_worker_state() {
    let source_root = tempfile::tempdir().unwrap();
    let source_data_dir = source_root.path().join("source-data");
    fs::create_dir_all(&source_data_dir).unwrap();
    let source_storage = Storage::open(source_data_dir.join("drive.db")).unwrap();
    source_storage.migrate().unwrap();
    let source_body = b"source-only backup blob";
    let (_, source_hash) = create_file_with_blob(
        &source_storage,
        &source_data_dir,
        "source-only.txt",
        source_body,
    );
    let backup_id = "restore-rollback-proof";
    let source_archive = source_root.path().join(format!("{backup_id}.sxdbackup"));
    source_storage
        .create_backup_v2_archive(
            &source_data_dir,
            &source_archive,
            &source_root.path().join("source-stage"),
            V2ArchiveIdentity {
                backup_id,
                created_at: &Utc::now().to_rfc3339(),
                source_build: "test",
            },
            V2Limits::default(),
        )
        .unwrap();

    let target_root = tempfile::tempdir().unwrap();
    let state = test_state(target_root.path().join("target-data"));
    let target_data_dir = state.data_dir();
    let prior_body = b"pre-restore referenced blob";
    let (prior_file_id, prior_hash) = create_file_with_blob(
        &state.storage,
        &target_data_dir,
        "prior-state.txt",
        prior_body,
    );
    // `export_backup_tables` covers product rows but intentionally excludes the
    // operational backup job whose failure is expected below.
    let prior_product_tables =
        serde_json::to_value(state.storage.export_backup_tables().unwrap()).unwrap();
    let archive_dir = target_data_dir.join("backups");
    fs::create_dir_all(&archive_dir).unwrap();
    fs::copy(
        &source_archive,
        archive_dir.join(format!("{backup_id}.sxdbackup")),
    )
    .unwrap();

    let restore = state
        .storage
        .enqueue_scheduled_backup_job("restore", backup_id, "system@local")
        .unwrap();
    restore_support::fail_next_after_reverse_deletes(&target_data_dir);
    let worker = spawn_backup_worker(state.clone());

    for _ in 0..400 {
        let job = state.storage.get_backup_job(&restore.id).unwrap().unwrap();
        if job.status == "failed" && state.backup_maintenance().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    worker.abort();

    let job = state.storage.get_backup_job(&restore.id).unwrap().unwrap();
    assert_eq!(job.status, "failed");
    assert!(state.backup_maintenance().is_none());
    assert!(!target_data_dir
        .join("backups")
        .join(".staging")
        .join(format!(".{}.restore-stage", restore.id))
        .exists());
    assert_eq!(
        serde_json::to_value(state.storage.export_backup_tables().unwrap()).unwrap(),
        prior_product_tables,
        "a rejected restore must preserve every backed-up relational row"
    );

    let conn = state.storage.conn.lock().unwrap();
    let stored_hash: String = conn
        .query_row(
            "SELECT content_hash FROM files WHERE id = ?1",
            [&prior_file_id],
            |row| row.get(0),
        )
        .unwrap();
    let file_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
        .unwrap();
    drop(conn);
    assert_eq!(stored_hash, prior_hash);
    assert_eq!(file_count, 1);
    assert_eq!(
        fs::read(blob::blob_file_path(&target_data_dir, &prior_hash).unwrap()).unwrap(),
        prior_body
    );
    assert!(!blob::blob_file_path(&target_data_dir, &source_hash)
        .unwrap()
        .exists());
}

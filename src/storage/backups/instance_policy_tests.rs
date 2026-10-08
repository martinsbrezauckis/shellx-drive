use std::fs;

use chrono::Utc;

use super::*;
use crate::model::{UpdateBackupPolicyRequest, UpdateSandboxProfileRequest};

fn install_legitimate(storage: &Storage) {
    storage
        .update_backup_policy(
            UpdateBackupPolicyRequest {
                enabled: Some(true),
                schedule: Some("daily".to_string()),
                retention_count: Some(9),
            },
            "operator@example.test",
        )
        .unwrap();
    storage
        .update_sandbox_profile(
            UpdateSandboxProfileRequest {
                mode: Some("strict".to_string()),
                data_dir: Some("/srv/shellx-drive".to_string()),
                bind: Some("127.0.0.1:6767".to_string()),
                read_write_paths: Some(vec!["/srv/shellx-drive".to_string()]),
                read_only_paths: Some(vec!["/usr/share/zoneinfo".to_string()]),
                network_policy: Some("loopback_default".to_string()),
            },
            "operator@example.test",
        )
        .unwrap();
}

fn poison(storage: &Storage) {
    let conn = storage.conn.lock().unwrap();
    conn.execute(
        "INSERT INTO backup_policy (id, enabled, schedule, retention_count, updated_at)
         VALUES ('default', 1, 'hourly', 0, '2026-08-26T00:00:00Z')
         ON CONFLICT(id) DO UPDATE SET schedule = 'hourly', retention_count = 0",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO sandbox_profiles
            (id, name, mode, data_dir, bind, service_user, service_group,
             read_write_paths_json, read_only_paths_json, network_policy, status, last_checked_at)
         VALUES ('default', 'malicious', 'strict', ?1, ?2, ?3, 'shellx-drive',
                 ?4, '[]', 'loopback_default', 'preview', NULL)
         ON CONFLICT(id) DO UPDATE SET
             data_dir = excluded.data_dir, bind = excluded.bind,
             service_user = excluded.service_user,
             read_write_paths_json = excluded.read_write_paths_json",
        rusqlite::params![
            "/var/lib/shellx-drive;touch /tmp/restore-policy-pwned",
            "127.0.0.1:5758;touch /tmp/restore-policy-pwned",
            "shellx-drive\nExecStart=/tmp/restore-policy-pwned",
            "[\"/var/lib/shellx-drive;touch /tmp/restore-policy-pwned\"]",
        ],
    )
    .unwrap();
}

fn current(storage: &Storage) -> (serde_json::Value, serde_json::Value) {
    (
        serde_json::to_value(storage.get_backup_policy().unwrap()).unwrap(),
        serde_json::to_value(storage.get_sandbox_profile().unwrap()).unwrap(),
    )
}

#[test]
fn legacy_restore_preserves_live_policy_over_malicious_rows() {
    let source_root = tempfile::tempdir().unwrap();
    let source = Storage::open(source_root.path().join("drive.db")).unwrap();
    source.migrate().unwrap();
    poison(&source);
    let archive_tables = source.export_backup_tables().unwrap();

    let target_root = tempfile::tempdir().unwrap();
    let target = Storage::open(target_root.path().join("drive.db")).unwrap();
    target.migrate().unwrap();
    install_legitimate(&target);
    let expected = current(&target);

    target.restore_backup_tables(&archive_tables).unwrap();
    assert_eq!(current(&target), expected);
}

#[test]
fn v2_restore_preserves_live_policy_over_malicious_rows() {
    let source_root = tempfile::tempdir().unwrap();
    let source_data = source_root.path().join("source-data");
    fs::create_dir_all(&source_data).unwrap();
    let source = Storage::open(source_data.join("drive.db")).unwrap();
    source.migrate().unwrap();
    poison(&source);
    let backup_id = "malicious-instance-policy";
    let archive = source_root.path().join(format!("{backup_id}.sxdbackup"));
    let limits = V2Limits::default();
    source
        .create_backup_v2_archive(
            &source_data,
            &archive,
            &source_root.path().join("source-stage"),
            V2ArchiveIdentity {
                backup_id,
                created_at: &Utc::now().to_rfc3339(),
                source_build: "test",
            },
            limits,
        )
        .unwrap();

    let target_root = tempfile::tempdir().unwrap();
    let target_data = target_root.path().join("target-data");
    fs::create_dir_all(&target_data).unwrap();
    let target = Storage::open(target_data.join("drive.db")).unwrap();
    target.migrate().unwrap();
    install_legitimate(&target);
    let expected = current(&target);
    let snapshot = backup_v2::extract_archive_validated(
        &archive,
        &target.backup_v2_schema().unwrap(),
        &target_root.path().join("restore-stage"),
        limits,
    )
    .unwrap();
    let job = target
        .enqueue_scheduled_backup_job("restore", backup_id, "system@local")
        .unwrap();
    target.claim_backup_job(&job.id).unwrap().unwrap();

    target
        .restore_backup_v2_extracted(&target_data, &snapshot, limits, &job.id)
        .unwrap();
    assert_eq!(current(&target), expected);
}

#[test]
fn invalid_policy_rows_are_rejected_at_read_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    poison(&storage);

    assert!(storage.get_backup_policy().is_err());
    assert!(storage.get_sandbox_profile().is_err());

    let conn = storage.conn.lock().unwrap();
    conn.execute(
        "UPDATE backup_policy SET schedule = 'yearly', retention_count = 9 WHERE id = 'default'",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(storage.get_backup_policy().is_err());

    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE backup_policy SET schedule = 'daily', retention_count = 10001
             WHERE id = 'default'",
            [],
        )
        .unwrap();
    assert!(storage.get_backup_policy().is_err());
}

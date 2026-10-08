use std::fs;

use chrono::Utc;

use super::*;
use crate::{
    backup_v2::{self, V2ArchiveIdentity, V2Limits},
    model::BackupTable,
};

fn install_and_seed_local_controls(storage: &Storage) {
    let conn = storage.conn.lock().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS desktop_agent_devices (
             id TEXT PRIMARY KEY, owner_account_id TEXT NOT NULL,
             owner_session_id TEXT NOT NULL, owner_security_version INTEGER NOT NULL,
             pair_fingerprint TEXT NOT NULL, credential_hash TEXT NOT NULL,
             platform TEXT NOT NULL, app_version TEXT NOT NULL, state TEXT NOT NULL,
             created_at TEXT NOT NULL, last_seen_at TEXT, last_ready_at TEXT,
             frozen_at TEXT, retired_at TEXT, revoked_at TEXT
         );
         CREATE TABLE IF NOT EXISTS desktop_agent_commands (
             id TEXT PRIMARY KEY, owner_account_id TEXT NOT NULL, device_id TEXT,
             target_key TEXT NOT NULL, requester_kind TEXT NOT NULL,
             requester_id TEXT NOT NULL, requester_principal_id TEXT NOT NULL,
             owner_is_admin_at_enqueue INTEGER NOT NULL,
             owner_security_version INTEGER NOT NULL, kind TEXT NOT NULL,
             payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL,
             request_id TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL,
             lease_id TEXT, lease_expires_at TEXT, lease_event_sequence INTEGER,
             created_at TEXT NOT NULL, accepted_at TEXT, started_at TEXT,
             finished_at TEXT, terminal_code TEXT, result_code TEXT,
             FOREIGN KEY (device_id) REFERENCES desktop_agent_devices(id) ON DELETE SET NULL,
             UNIQUE(owner_account_id, requester_principal_id, target_key, request_id)
         );
         CREATE TABLE IF NOT EXISTS desktop_agent_command_events (
             command_id TEXT NOT NULL, sequence INTEGER NOT NULL, at TEXT NOT NULL,
             status TEXT NOT NULL, phase TEXT, progress_basis_points INTEGER,
             terminal_code TEXT, result_code TEXT,
             PRIMARY KEY (command_id, sequence),
             FOREIGN KEY (command_id) REFERENCES desktop_agent_commands(id) ON DELETE CASCADE
         );",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO desktop_agent_devices (
             id, owner_account_id, owner_session_id, owner_security_version,
             pair_fingerprint, credential_hash, platform, app_version, state, created_at
         ) VALUES ('device', 'owner', 'session', 1, 'fingerprint', 'secret-hash',
                   'linux', '0.1.0', 'active', '2026-09-07T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO desktop_agent_commands (
             id, owner_account_id, device_id, target_key, requester_kind, requester_id,
             requester_principal_id, owner_is_admin_at_enqueue, owner_security_version,
             kind, payload_json, payload_hash, request_id, expires_at, status, lease_id,
             lease_expires_at, lease_event_sequence, created_at
         ) VALUES ('command', 'owner', 'device', 'device', 'user_session', 'session',
                   'session', 0, 1, 'sync_now', '{}', 'payload-hash', 'request',
                   '2026-09-07T00:05:00Z', 'leased', 'lease', '2026-09-07T00:01:00Z',
                   1, '2026-09-07T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO desktop_agent_command_events
             (command_id, sequence, at, status)
         VALUES ('command', 1, '2026-09-07T00:00:00Z', 'leased')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO desktop_agent_disconnect_completions
             (command_id, device_id, owner_session_id, owner_security_version, lease_id,
              pair_fingerprint, capability_hash, expires_at, retirement_authorized_at)
         VALUES ('command', 'device', 'session', 1, 'lease', 'fingerprint', 'capability-hash',
                 '2026-09-07T00:05:00Z', '2026-09-07T00:00:30Z')",
        [],
    )
    .unwrap();
}

fn local_control_counts(storage: &Storage) -> [i64; 4] {
    let conn = storage.conn.lock().unwrap();
    restore_desktop_agent::LOCAL_DESKTOP_AGENT_TABLES.map(|table| {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    })
}

fn storage(root: &std::path::Path) -> Storage {
    let storage = Storage::open(root.join("drive.db")).unwrap();
    storage.migrate().unwrap();
    storage
}

#[test]
fn legacy_restore_purges_target_local_desktop_agent_controls() {
    let source_root = tempfile::tempdir().unwrap();
    let source = storage(source_root.path());
    let archive = source.export_backup_tables().unwrap();
    assert!(archive.iter().all(|table| {
        !restore_desktop_agent::LOCAL_DESKTOP_AGENT_TABLES.contains(&table.name.as_str())
    }));

    let target_root = tempfile::tempdir().unwrap();
    let target = storage(target_root.path());
    install_and_seed_local_controls(&target);
    assert_eq!(local_control_counts(&target), [1, 1, 1, 1]);

    target.restore_backup_tables(&archive).unwrap();
    assert_eq!(local_control_counts(&target), [0, 0, 0, 0]);
}

#[test]
fn v2_restore_purges_target_local_desktop_agent_controls() {
    let source_root = tempfile::tempdir().unwrap();
    let source_data = source_root.path().join("source-data");
    fs::create_dir_all(&source_data).unwrap();
    let source = storage(&source_data);
    let backup_id = "desktop-agent-controls";
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
    let target = storage(&target_data);
    install_and_seed_local_controls(&target);
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
    assert_eq!(local_control_counts(&target), [0, 0, 0, 0]);
}

#[test]
fn local_desktop_agent_tables_are_rejected_from_legacy_inventory() {
    let root = tempfile::tempdir().unwrap();
    let storage = storage(root.path());
    let mut archive = storage.export_backup_tables().unwrap();
    archive.push(BackupTable {
        name: "desktop_agent_devices".to_string(),
        columns: Vec::new(),
        rows: Vec::new(),
    });

    let error = storage.validate_backup_tables(&archive).unwrap_err();
    assert!(error.to_string().contains("local desktop-agent table"));
}

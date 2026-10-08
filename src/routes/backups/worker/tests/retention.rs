use std::path::{Path, PathBuf};

use super::{test_state, write_test_v2_generation};
use crate::{
    backup_v2,
    model::{BackupTable, UpdateBackupPolicyRequest},
    routes::backups::{list_backup_metadata, recover_backup_state},
    storage::ManagedBackupGeneration,
};

use super::super::super::catalog::{
    apply_v2_retention, v2_backup_path, v2_sidecar_path, v2_staging_root,
};

fn write_portable_v2_generation(data_dir: &Path, backup_id: &str, created_at: &str) -> PathBuf {
    let archive = v2_backup_path(data_dir, backup_id).unwrap();
    let tables = vec![BackupTable {
        name: "workspaces".to_string(),
        columns: vec!["id".to_string()],
        rows: Vec::new(),
    }];
    backup_v2::create_archive_atomic(
        &archive,
        &v2_staging_root(data_dir),
        backup_v2::V2BuildInput {
            backup_id,
            created_at,
            source_build: "retention-test",
            tables: &tables,
            blobs: &[],
        },
        backup_v2::V2Limits::default(),
    )
    .unwrap();
    archive
}

#[test]
fn portable_only_generation_does_not_control_destructive_retention() {
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

    let old_local = write_test_v2_generation(
        data_dir.path(),
        "retention-local-old",
        "2026-01-01T00:00:00Z",
    );
    let portable = write_portable_v2_generation(
        data_dir.path(),
        "retention-portable-future",
        "9999-01-01T00:00:00Z",
    );
    let new_local = write_test_v2_generation(
        data_dir.path(),
        "retention-local-new",
        "2026-01-02T00:00:00Z",
    );

    apply_v2_retention(&state).unwrap();

    assert!(!old_local.exists());
    assert!(new_local.exists());
    assert!(portable.exists());
    assert!(
        !v2_sidecar_path(data_dir.path(), "retention-portable-future")
            .unwrap()
            .exists()
    );
}

#[test]
fn retention_tombstone_blocks_exact_archive_replay_after_restart() {
    let data_dir = tempfile::tempdir().unwrap();
    let old_backup_id = "retention-replayed";
    let retained_backup_id = "retention-retained";
    let (replayed_archive, replayed_sidecar) = {
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
        let old_archive =
            write_test_v2_generation(data_dir.path(), old_backup_id, "2026-01-01T00:00:00Z");
        let old_sidecar = v2_sidecar_path(data_dir.path(), old_backup_id).unwrap();
        let replayed_archive = std::fs::read(&old_archive).unwrap();
        let replayed_sidecar = std::fs::read(&old_sidecar).unwrap();
        write_test_v2_generation(data_dir.path(), retained_backup_id, "2026-01-02T00:00:00Z");

        apply_v2_retention(&state).unwrap();
        assert!(!old_archive.exists());
        assert!(!old_sidecar.exists());
        (replayed_archive, replayed_sidecar)
    };

    // An exact byte-for-byte old pair can reappear from backup media after the
    // process stops. Opening the target database again executes compatibility
    // migration; recovery then attempts authenticated-sidecar reconciliation.
    let archive = v2_backup_path(data_dir.path(), old_backup_id).unwrap();
    let sidecar = v2_sidecar_path(data_dir.path(), old_backup_id).unwrap();
    std::fs::write(&archive, replayed_archive).unwrap();
    std::fs::write(&sidecar, replayed_sidecar).unwrap();

    let restarted = test_state(data_dir.path().to_path_buf());
    recover_backup_state(&restarted).unwrap();
    assert!(matches!(
        restarted
            .storage
            .managed_backup_generation(old_backup_id)
            .unwrap(),
        ManagedBackupGeneration::Tombstoned
    ));
    assert!(list_backup_metadata(&restarted)
        .unwrap()
        .iter()
        .all(|backup| backup.backup_id != old_backup_id));
    assert!(v2_backup_path(data_dir.path(), retained_backup_id)
        .unwrap()
        .exists());
}

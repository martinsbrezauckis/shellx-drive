use std::path::Path;

use chrono::Utc;

use super::human_item_sharing_tests::{
    access_generation, assert_private_workspace_invariant, create, grant, operator,
    private_mappings, recipient, storage, table,
};
use crate::{
    auth::{DriveCredential, WorkspacePermission},
    backup_v2::{self, V2BuildInput, V2Limits},
    error::ApiError,
    model::BackupTable,
    storage::Storage,
};

fn restore_as_v2(data_root: &Path, storage: &Storage, tables: &[BackupTable], backup_id: &str) {
    let archive = data_root.join(format!("{backup_id}.sxdbackup"));
    let limits = V2Limits::default();
    backup_v2::create_archive_atomic(
        &archive,
        &data_root.join(format!("{backup_id}-backup-stage")),
        V2BuildInput {
            backup_id,
            created_at: &Utc::now().to_rfc3339(),
            source_build: "test",
            tables,
            blobs: &[],
        },
        limits,
    )
    .unwrap();
    let snapshot = backup_v2::extract_archive_validated(
        &archive,
        &storage.backup_v2_schema().unwrap(),
        &data_root.join(format!("{backup_id}-restore-stage")),
        limits,
    )
    .unwrap();
    let job = storage
        .enqueue_scheduled_backup_job("restore", backup_id, "system@local")
        .unwrap();
    storage.claim_backup_job(&job.id).unwrap().unwrap();
    storage
        .restore_backup_v2_extracted(data_root, &snapshot, limits, &job.id)
        .unwrap();
}

#[test]
fn v2_restore_accepts_the_complete_pre_item_sharing_table_pair_omission() {
    let (directory, storage, _) = storage();
    let mut historical = storage.export_backup_tables().unwrap();
    historical.retain(|table| {
        !crate::backup_schema_compatibility::HISTORICALLY_OMITTED_HUMAN_ITEM_SHARING_TABLES
            .contains(&table.name.as_str())
    });
    let live_generation = access_generation(&storage);

    restore_as_v2(directory.path(), &storage, &historical, "pre-sharing-v2");

    assert_eq!(access_generation(&storage), live_generation + 1);
    assert_private_workspace_invariant(&storage);
}

#[test]
fn v2_restore_keeps_live_grant_authority_and_advances_the_epoch() {
    let (directory, storage, workspace_id) = storage();
    let archived_root = create(&storage, &workspace_id, None, "Archived V2 grant");
    let current_root = create(&storage, &workspace_id, None, "Current V2 grant");
    let (archived_grant, _) = storage
        .create_human_item_grant(
            &archived_root,
            &grant("account", Some("backup-recipient@example.test")),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let archived = storage.export_backup_tables().unwrap();
    storage
        .revoke_human_item_grant(&archived_grant.id, &operator(), &DriveCredential::Operator)
        .unwrap();
    storage
        .create_human_item_grant(
            &current_root,
            &grant("account", Some("backup-recipient@example.test")),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let live_generation = access_generation(&storage);
    let live_mappings = private_mappings(&storage);

    restore_as_v2(directory.path(), &storage, &archived, "grant-authority-v2");

    assert_eq!(access_generation(&storage), live_generation + 1);
    assert_eq!(private_mappings(&storage), live_mappings);
    assert_private_workspace_invariant(&storage);
    assert!(matches!(
        storage.ensure_item_permission(&archived_root, &recipient(), WorkspacePermission::Read),
        Err(ApiError::Forbidden)
    ));
    assert!(storage
        .ensure_item_permission(&current_root, &recipient(), WorkspacePermission::Read)
        .is_ok());
}

#[test]
fn v2_restore_on_fresh_target_keeps_target_accounts_private_and_unshared() {
    let (_source_root, source, source_workspace) = storage();
    let archived_root = create(&source, &source_workspace, None, "Fresh-target V2 grant");
    source
        .create_human_item_grant(
            &archived_root,
            &grant("account", Some("backup-recipient@example.test")),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let archived = source.export_backup_tables().unwrap();
    let (target_root, target, _) = storage();
    let expected_mappings = private_mappings(&target);
    let live_generation = access_generation(&target);

    restore_as_v2(target_root.path(), &target, &archived, "fresh-target-v2");

    assert_eq!(access_generation(&target), live_generation + 1);
    assert_eq!(private_mappings(&target), expected_mappings);
    assert_private_workspace_invariant(&target);
    assert!(
        table(&target.export_backup_tables().unwrap(), "human_item_grants")
            .rows
            .is_empty()
    );
    assert!(matches!(
        target.ensure_item_permission(&archived_root, &recipient(), WorkspacePermission::Read),
        Err(ApiError::Forbidden)
    ));
}

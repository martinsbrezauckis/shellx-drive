use std::fs;

use chrono::Utc;
use rusqlite::params;

use crate::{
    backup_v2::{self, V2ArchiveIdentity, V2Limits},
    blob,
    model::{ContentWrite, CreateFileRequest, FileKind},
    storage::{validate_file_name, Storage, MAX_FILE_NAME_BYTES},
};

#[test]
fn v2_backup_rejects_invalid_file_name_before_publication() {
    let source_root = tempfile::tempdir().unwrap();
    let source_data_dir = source_root.path().join("source-data");
    fs::create_dir_all(&source_data_dir).unwrap();
    let source = Storage::open(source_data_dir.join("drive.db")).unwrap();
    source.migrate().unwrap();
    let (workspace, _, _) = source
        .create_workspace("Invalid name", "owner@example.test")
        .unwrap();
    let file_id = source
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: None,
                name: "valid.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0
        .id;
    source
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE files SET name = ?1 WHERE id = ?2",
            params!["x".repeat(256), &file_id],
        )
        .unwrap();
    let backup_id = "invalid-file-name";
    let archive = source_root.path().join(format!("{backup_id}.sxdbackup"));
    let error = source
        .create_backup_v2_archive(
            &source_data_dir,
            &archive,
            &source_root.path().join("stage"),
            V2ArchiveIdentity {
                backup_id,
                created_at: &Utc::now().to_rfc3339(),
                source_build: "test",
            },
            V2Limits::default(),
        )
        .unwrap_err();

    assert!(error
        .to_string()
        .contains(&format!("file {file_id} has an invalid name")));
    assert!(!archive.exists());
}

#[test]
fn v2_backup_restore_preserves_canonical_derived_names_at_the_byte_limit() {
    let source_root = tempfile::tempdir().unwrap();
    let source_data = source_root.path().join("source-data");
    fs::create_dir_all(&source_data).unwrap();
    let source = Storage::open(source_data.join("drive.db")).unwrap();
    source.migrate().unwrap();
    let (workspace, _, _) = source
        .create_workspace("Derived names", "owner@example.test")
        .unwrap();
    let source_name = format!("{}x", "é".repeat(127));
    assert_eq!(source_name.len(), MAX_FILE_NAME_BYTES);
    let original = blob::put_blob(&source_data, b"original").unwrap();
    let (file, _) = source
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: None,
                name: source_name,
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some(original),
            8,
        )
        .unwrap();
    let (copy, _, _) = source.copy_file(&file.id, None, None).unwrap();
    assert_eq!(copy.name.len(), MAX_FILE_NAME_BYTES);
    assert_eq!(validate_file_name(&copy.name).unwrap(), copy.name);

    let current = blob::put_blob(&source_data, b"current").unwrap();
    source.put_content(&file.id, 1, &current, 7).unwrap();
    let stale = blob::put_blob(&source_data, b"stale").unwrap();
    let conflict = match source.put_content(&file.id, 1, &stale, 5).unwrap() {
        ContentWrite::Conflict(conflict) => conflict,
        ContentWrite::Updated { .. } => panic!("stale write unexpectedly updated the source"),
    };
    let conflict_file = source
        .get_file(&conflict.conflict_file_id)
        .unwrap()
        .unwrap();
    assert!(conflict_file.name.len() <= MAX_FILE_NAME_BYTES);
    assert!(!conflict_file.name.contains(':'));
    assert_eq!(
        validate_file_name(&conflict_file.name).unwrap(),
        conflict_file.name
    );

    let backup_id = "derived-names-byte-limit";
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
    let snapshot = backup_v2::extract_archive_validated(
        &archive,
        &target.backup_v2_schema().unwrap(),
        &target_root.path().join("restore-stage"),
        limits,
    )
    .unwrap();
    let restore = target
        .enqueue_scheduled_backup_job("restore", backup_id, "system@local")
        .unwrap();
    target.claim_backup_job(&restore.id).unwrap().unwrap();
    target
        .restore_backup_v2_extracted(&target_data, &snapshot, limits, &restore.id)
        .unwrap();

    assert_eq!(target.get_file(&copy.id).unwrap().unwrap().name, copy.name);
    assert_eq!(
        target.get_file(&conflict_file.id).unwrap().unwrap().name,
        conflict_file.name
    );
}

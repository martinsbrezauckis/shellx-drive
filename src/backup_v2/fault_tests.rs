use super::test_faults::{fail_archive_writes_after, override_available_space};
use super::*;

fn tables_referencing_blob(hash: &str) -> Vec<BackupTable> {
    vec![BackupTable {
        name: "files".to_string(),
        columns: vec!["id".to_string(), "content_hash".to_string()],
        rows: vec![vec![
            Value::String("f1".to_string()),
            Value::String(hash.to_string()),
        ]],
    }]
}

fn assert_generation_artifacts_absent(root: &Path, backup_id: &str) {
    assert!(!root
        .join(format!("{backup_id}.{ARCHIVE_EXTENSION}"))
        .exists());
    assert!(!root
        .join(format!("{backup_id}.{ARCHIVE_EXTENSION}.partial"))
        .exists());
    assert!(!root.join(format!(".{backup_id}.v2-stage")).exists());
}

#[test]
fn archive_preflight_low_space_leaves_no_artifacts_or_mutates_source_blobs() {
    let root = tempfile::tempdir().unwrap();
    let body = b"low-space source blob".to_vec();
    let hash = sha256_bytes(&body);
    let blob_path = root.path().join("blob");
    fs::write(&blob_path, &body).unwrap();
    let tables = tables_referencing_blob(&hash);
    let _space = override_available_space(0);

    let error = create_archive_atomic(
        &root.path().join("low-space.sxdbackup"),
        root.path(),
        V2BuildInput {
            backup_id: "low-space",
            created_at: "2026-08-25T00:00:00Z",
            source_build: "test",
            tables: &tables,
            blobs: &[V2BlobSource {
                hash: hash.clone(),
                path: blob_path.clone(),
            }],
        },
        V2Limits::default(),
    )
    .unwrap_err();

    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    assert_generation_artifacts_absent(root.path(), "low-space");
    assert_eq!(fs::read(&blob_path).unwrap(), body);
    assert_eq!(sha256_bytes(&fs::read(&blob_path).unwrap()), hash);
}

#[test]
fn archive_partial_write_enospc_leaves_no_artifacts_or_mutates_source_blobs() {
    let root = tempfile::tempdir().unwrap();
    let body = b"partial-write source blob".to_vec();
    let hash = sha256_bytes(&body);
    let blob_path = root.path().join("blob");
    fs::write(&blob_path, &body).unwrap();
    let tables = tables_referencing_blob(&hash);
    let _write_failure = fail_archive_writes_after(TAR_BLOCK_BYTES + 1);

    let error = create_archive_atomic(
        &root.path().join("partial-write.sxdbackup"),
        root.path(),
        V2BuildInput {
            backup_id: "partial-write",
            created_at: "2026-08-25T00:00:00Z",
            source_build: "test",
            tables: &tables,
            blobs: &[V2BlobSource {
                hash: hash.clone(),
                path: blob_path.clone(),
            }],
        },
        V2Limits::default(),
    )
    .unwrap_err();

    assert!(matches!(error, ApiError::Io(error) if error.raw_os_error() == Some(libc::ENOSPC)));
    assert_generation_artifacts_absent(root.path(), "partial-write");
    assert_eq!(fs::read(&blob_path).unwrap(), body);
    assert_eq!(sha256_bytes(&fs::read(&blob_path).unwrap()), hash);
}

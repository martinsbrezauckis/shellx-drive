use super::test_state;
use crate::{
    backup_v2::{self, V2BuildInput, V2Limits},
    model::BackupTable,
    routes::backups::{catalog, worker::provenance},
    server::AppState,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn archive_fixture(path: &Path, staging: &Path, kind: &str) -> Vec<backup_v2::V2TableSchema> {
    let tables = vec![BackupTable {
        name: "receipts".to_string(),
        columns: vec!["id".to_string(), "kind".to_string()],
        rows: vec![vec![json!("receipt-1"), json!(kind)]],
    }];
    backup_v2::create_archive_atomic(
        path,
        staging,
        V2BuildInput {
            backup_id: "archive-binding",
            created_at: "2026-10-06T00:00:00Z",
            source_build: "0.1.1+fixture",
            tables: &tables,
            blobs: &[],
        },
        V2Limits::default(),
    )
    .unwrap();
    backup_v2::schema_from_tables(&tables)
}

fn record_managed_archive(
    state: &AppState,
    bytes: &[u8],
    summary: &backup_v2::V2ValidationSummary,
) {
    let digest = hex::encode(Sha256::digest(bytes));
    let metadata = catalog::metadata_from_v2_manifest(
        &summary.manifest,
        summary.archive_bytes,
        "archive-binding-job",
    );
    catalog::write_v2_sidecar(
        &state.data_dir(),
        catalog::V2SidecarPayload {
            metadata,
            archive_sha256: digest.clone(),
        },
    )
    .unwrap();
    state
        .storage
        .record_managed_backup_publication("archive-binding", &digest, "2026-10-06T00:00:00Z")
        .unwrap();
}

#[test]
fn managed_creation_authenticates_the_writer_not_a_replaced_path() {
    let root = tempfile::tempdir().unwrap();
    let state = test_state(root.path().to_path_buf());
    let archive = catalog::v2_backup_path(root.path(), "archive-binding").unwrap();
    let created = state
        .storage
        .create_backup_v2_archive(
            root.path(),
            &archive,
            &root.path().join("staging"),
            backup_v2::V2ArchiveIdentity {
                backup_id: "archive-binding",
                created_at: "2026-10-06T00:00:00Z",
                source_build: "0.1.1+fixture",
            },
            V2Limits::default(),
        )
        .unwrap();
    let written = fs::read(&archive).unwrap();
    assert_eq!(
        created.archive_sha256,
        hex::encode(Sha256::digest(&written))
    );
    assert_eq!(created.archive_bytes, written.len() as u64);
    assert_eq!(created.manifest.backup_id, "archive-binding");

    let alternate_dir = root.path().join("alternate");
    fs::create_dir(&alternate_dir).unwrap();
    let alternate = alternate_dir.join(archive.file_name().unwrap());
    let schema = archive_fixture(&alternate, root.path(), "changed");
    fs::copy(&alternate, &archive).unwrap();
    let changed = backup_v2::validate_archive(&archive, &schema, V2Limits::default()).unwrap();
    state
        .storage
        .record_managed_backup_publication(
            "archive-binding",
            &created.archive_sha256,
            "2026-10-06T00:00:00Z",
        )
        .unwrap();
    assert_ne!(changed.archive_sha256, created.archive_sha256);
    assert!(provenance::verify_v2_archive(
        &state,
        "archive-binding",
        &changed.archive_sha256,
        true,
    )
    .is_err());
}

#[test]
fn managed_provenance_uses_the_validated_and_extracted_bytes() {
    let root = tempfile::tempdir().unwrap();
    let state = test_state(root.path().to_path_buf());
    let archive = catalog::v2_backup_path(root.path(), "archive-binding").unwrap();
    let schema = archive_fixture(&archive, root.path(), "trusted");
    let bytes = fs::read(&archive).unwrap();
    let summary = backup_v2::validate_archive(&archive, &schema, V2Limits::default()).unwrap();
    record_managed_archive(&state, &bytes, &summary);
    let snapshot = backup_v2::extract_archive_validated(
        &archive,
        &schema,
        &root.path().join("extracted"),
        V2Limits::default(),
    )
    .unwrap();

    let digest = hex::encode(Sha256::digest(&bytes));
    assert_eq!(summary.archive_sha256, digest);
    assert_eq!(snapshot.archive_sha256, digest);
    assert!(provenance::verify_v2_archive(
        &state,
        "archive-binding",
        &summary.archive_sha256,
        summary.portable_metadata.is_some(),
    )
    .unwrap()
    .is_some());
    assert!(provenance::verify_v2_archive(
        &state,
        "archive-binding",
        &snapshot.archive_sha256,
        snapshot.portable_metadata.is_some(),
    )
    .unwrap()
    .is_some());
    assert!(fs::read_to_string(&snapshot.table_paths[0])
        .unwrap()
        .contains("trusted"));
}

#[test]
fn restored_original_path_cannot_authenticate_an_altered_extracted_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let state = test_state(root.path().to_path_buf());
    let archive = catalog::v2_backup_path(root.path(), "archive-binding").unwrap();
    let schema = archive_fixture(&archive, root.path(), "trusted");
    let authentic_bytes = fs::read(&archive).unwrap();
    let authentic = backup_v2::validate_archive(&archive, &schema, V2Limits::default()).unwrap();
    record_managed_archive(&state, &authentic_bytes, &authentic);

    let alternate_dir = root.path().join("alternate");
    fs::create_dir(&alternate_dir).unwrap();
    let alternate = alternate_dir.join(archive.file_name().unwrap());
    archive_fixture(&alternate, root.path(), "changed");
    let changed_bytes = fs::read(&alternate).unwrap();
    fs::write(&archive, &changed_bytes).unwrap();
    let changed = backup_v2::validate_archive(&archive, &schema, V2Limits::default()).unwrap();
    let snapshot = backup_v2::extract_archive_validated(
        &archive,
        &schema,
        &root.path().join("extracted"),
        V2Limits::default(),
    )
    .unwrap();

    // The original pathname again has authentic bytes. Only the digests of
    // the streams already validated/extracted may authenticate their results.
    fs::write(&archive, &authentic_bytes).unwrap();
    assert!(provenance::verify_v2_archive(
        &state,
        "archive-binding",
        &catalog::hash_file_streaming(&archive, V2Limits::default().max_archive_bytes).unwrap(),
        true,
    )
    .is_ok());
    assert_eq!(
        snapshot.archive_sha256,
        hex::encode(Sha256::digest(&changed_bytes))
    );
    assert_eq!(changed.archive_sha256, snapshot.archive_sha256);
    assert_ne!(snapshot.archive_sha256, authentic.archive_sha256);
    assert!(provenance::verify_v2_archive(
        &state,
        "archive-binding",
        &snapshot.archive_sha256,
        snapshot.portable_metadata.is_some(),
    )
    .is_err());
    assert!(provenance::verify_v2_archive(
        &state,
        "archive-binding",
        &changed.archive_sha256,
        changed.portable_metadata.is_some(),
    )
    .is_err());
    assert!(fs::read_to_string(&snapshot.table_paths[0])
        .unwrap()
        .contains("changed"));
}

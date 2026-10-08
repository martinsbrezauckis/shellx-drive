use std::io::{Seek, SeekFrom};

use super::*;

#[derive(Clone)]
struct RawEntry {
    path: String,
    entry_type: u8,
    body: Vec<u8>,
}

fn fixture_tables(hash: &str) -> Vec<BackupTable> {
    vec![
        BackupTable {
            name: "receipts".to_string(),
            columns: vec!["id".to_string(), "kind".to_string()],
            rows: vec![vec![
                Value::String("r1".to_string()),
                Value::String("test".to_string()),
            ]],
        },
        BackupTable {
            name: "files".to_string(),
            columns: vec!["id".to_string(), "content_hash".to_string()],
            rows: vec![vec![
                Value::String("f1".to_string()),
                Value::String(hash.to_string()),
            ]],
        },
    ]
}

#[test]
fn generation_free_space_requirement_rejects_overflow_before_staging() {
    let root = tempfile::tempdir().unwrap();
    assert!(matches!(
        ensure_generation_staging_free_space(root.path(), u64::MAX),
        Err(ApiError::PayloadTooLarge(_))
    ));
}

fn create_fixture(root: &Path) -> (PathBuf, Vec<V2TableSchema>, Vec<u8>) {
    let body = b"raw backup body\0with bytes".to_vec();
    let hash = sha256_bytes(&body);
    let blob_path = root.join("blob");
    fs::write(&blob_path, &body).unwrap();
    let tables = fixture_tables(&hash);
    let schema = schema_from_tables(&tables);
    let archive = root.join("fixture.sxdbackup");
    create_archive_atomic(
        &archive,
        root,
        V2BuildInput {
            backup_id: "fixture",
            created_at: "2026-07-16T00:00:00Z",
            source_build: "0.1.0+fixture",
            tables: &tables,
            blobs: &[V2BlobSource {
                hash,
                path: blob_path,
            }],
        },
        V2Limits::default(),
    )
    .unwrap();
    (archive, schema, body)
}

#[test]
fn deterministic_archive_streams_raw_blobs_and_validates() {
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let (first, schema, body) = create_fixture(first_root.path());
    let (second, _, _) = create_fixture(second_root.path());
    let first_bytes = fs::read(&first).unwrap();
    let second_bytes = fs::read(&second).unwrap();
    assert_eq!(first_bytes, second_bytes);
    assert!(first_bytes.windows(body.len()).any(|window| window == body));
    let encoded = base64::engine::general_purpose::STANDARD.encode(&body);
    assert!(!first_bytes
        .windows(encoded.len())
        .any(|window| window == encoded.as_bytes()));

    let summary = validate_archive(&first, &schema, V2Limits::default()).unwrap();
    assert_eq!(summary.manifest.format, FORMAT);
    assert_eq!(summary.manifest.totals.content_bytes, body.len() as u64);
    assert_eq!(summary.archive_bytes, first_bytes.len() as u64);
}

#[test]
fn portable_integrity_envelope_rejects_corruption_and_wrong_format() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let envelope_offset = nth_entry_data_offset(&archive, 1);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&archive)
        .unwrap();
    file.seek(SeekFrom::Start(envelope_offset)).unwrap();
    let mut envelope = vec![0u8; 1024];
    let read = file.read(&mut envelope).unwrap();
    let backup_id = envelope[..read]
        .windows(b"\"backup_id\":\"fixture".len())
        .position(|window| window == b"\"backup_id\":\"fixture")
        .unwrap()
        + b"\"backup_id\":\"".len();
    file.seek(SeekFrom::Start(envelope_offset + backup_id as u64))
        .unwrap();
    file.write_all(if envelope[backup_id] == b'0' {
        b"1"
    } else {
        b"0"
    })
    .unwrap();
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error
        .to_string()
        .contains("portable integrity envelope does not match"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let (mut manifest, entries) = read_raw_archive(&archive);
    manifest.portable_integrity = Some(V2PortableIntegrityDescriptor {
        format: "wrong-format".to_string(),
        version: PORTABLE_INTEGRITY_VERSION,
        entry_path: PORTABLE_INTEGRITY_PATH.to_string(),
    });
    write_raw_archive(&archive, &manifest, &entries);
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error
        .to_string()
        .contains("portable integrity descriptor is unsupported"));
}

#[test]
fn pre_replacement_upload_session_columns_accept_only_the_two_historical_shapes() {
    let expected = [
        "id",
        "workspace_id",
        "actor_email",
        "parent_id",
        "name",
        "total_size",
        "received_bytes",
        "completed",
        "canceled",
        "file_id",
        "created_at",
        "updated_at",
        "canceled_at",
        "path",
        "target_file_id",
        "base_revision",
        "completion_receipt_id",
        "completion_current_revision",
        "quota_reservation_bytes",
        "duplicate_policy",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    let pre_policy = expected
        .iter()
        .filter(|column| {
            !matches!(
                column.as_str(),
                "target_file_id"
                    | "base_revision"
                    | "completion_receipt_id"
                    | "completion_current_revision"
                    | "quota_reservation_bytes"
                    | "duplicate_policy"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let policy_retained = expected
        .iter()
        .filter(|column| {
            !matches!(
                column.as_str(),
                "target_file_id"
                    | "base_revision"
                    | "completion_receipt_id"
                    | "completion_current_revision"
                    | "quota_reservation_bytes"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    assert!(backup_columns_are_compatible(
        "upload_sessions",
        &pre_policy,
        &expected
    ));
    assert!(backup_columns_are_compatible(
        "upload_sessions",
        &policy_retained,
        &expected
    ));
    let unexpected = expected
        .iter()
        .filter(|column| column.as_str() != "path")
        .cloned()
        .collect::<Vec<_>>();
    assert!(!backup_columns_are_compatible(
        "upload_sessions",
        &unexpected,
        &expected
    ));
    assert!(!backup_columns_are_compatible(
        "files",
        &pre_policy,
        &expected
    ));
}

#[test]
fn partial_or_truncated_archive_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let length = fs::metadata(&archive).unwrap().len();
    OpenOptions::new()
        .write(true)
        .open(&archive)
        .unwrap()
        .set_len(length - 1)
        .unwrap();
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("archive length"));
}

#[test]
fn traversal_and_non_regular_entries_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    mutate_nth_header(&archive, 1, |header| {
        header[..100].fill(0);
        header[..13].copy_from_slice(b"../escape.txt");
    });
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("traverses"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    mutate_nth_header(&archive, 1, |header| header[156] = b'2');
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("not a regular file"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    mutate_nth_header(&archive, 1, |header| header[156] = b'3');
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("not a regular file"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    mutate_nth_header(&archive, 1, |header| {
        header[..100].fill(0);
        header[..11].copy_from_slice(b"C:/evil.txt");
    });
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("absolute"));
}

#[test]
fn duplicate_or_out_of_order_archive_paths_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    mutate_nth_header(&archive, 3, |header| {
        header[..100].fill(0);
        let path = b"tables/00-receipts.jsonl";
        header[..path.len()].copy_from_slice(path);
    });
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error
        .to_string()
        .contains("duplicate, unknown, or out of order"));
}

#[test]
fn blob_hash_mismatch_is_rejected_without_buffering_the_body() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let blob_data_offset = nth_entry_data_offset(&archive, 4);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&archive)
        .unwrap();
    file.seek(SeekFrom::Start(blob_data_offset)).unwrap();
    file.write_all(b"X").unwrap();
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("content hash does not match"));
}

#[test]
fn table_hash_and_tar_checksum_mismatches_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let table_data_offset = nth_entry_data_offset(&archive, 2);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&archive)
        .unwrap();
    file.seek(SeekFrom::Start(table_data_offset)).unwrap();
    let mut table_body = vec![0u8; 256];
    let read = file.read(&mut table_body).unwrap();
    let offset = table_body[..read]
        .windows(4)
        .position(|window| window == b"\"r1\"")
        .unwrap();
    file.seek(SeekFrom::Start(table_data_offset + offset as u64 + 2))
        .unwrap();
    file.write_all(b"2").unwrap();
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("table receipts hash"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&archive)
        .unwrap();
    file.seek(SeekFrom::Start(10)).unwrap();
    file.write_all(b"X").unwrap();
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("checksum"));
}

#[test]
fn manifest_count_and_size_limits_fail_before_entry_processing() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let limits = V2Limits {
        max_manifest_bytes: 1,
        ..V2Limits::default()
    };
    let error = validate_archive(&archive, &schema, limits).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    assert!(error.to_string().contains("manifest"));

    let limits = V2Limits {
        max_rows: 1,
        ..V2Limits::default()
    };
    let error = validate_archive(&archive, &schema, limits).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));

    let limits = V2Limits {
        max_content_bytes: 1,
        ..V2Limits::default()
    };
    let error = validate_archive(&archive, &schema, limits).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
}

#[test]
fn wrong_schema_and_oversized_jsonl_lines_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let mut wrong_schema = schema.clone();
    wrong_schema[1].columns[1] = "different".to_string();
    let error = validate_archive(&archive, &wrong_schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("schema fingerprint"));

    let limits = V2Limits {
        max_line_bytes: 4,
        ..V2Limits::default()
    };
    let error = validate_archive(&archive, &schema, limits).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
}

#[test]
fn staged_table_budget_is_aggregate_across_the_catalog() {
    let root = tempfile::tempdir().unwrap();
    let first_limits = V2Limits::default();
    let first = V2TableStageWriter::new(
        root.path(),
        0,
        "first",
        vec!["id".to_string()],
        first_limits,
        0,
    )
    .unwrap();
    let (first, _) = first.finish().unwrap();
    let first_bytes = first.descriptor.byte_length;
    assert!(first_bytes > 1);

    let aggregate_limits = V2Limits {
        max_archive_bytes: first_bytes + 1,
        ..V2Limits::default()
    };
    let error = match V2TableStageWriter::new(
        root.path(),
        1,
        "second",
        vec!["id".to_string()],
        aggregate_limits,
        first_bytes,
    ) {
        Ok(_) => panic!("second staged table unexpectedly fit the aggregate byte budget"),
        Err(error) => error,
    };
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    assert!(error.to_string().contains("staged tables"));
}

#[test]
fn missing_and_extra_blob_catalog_entries_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let (mut manifest, mut entries) = read_raw_archive(&archive);
    manifest.blobs.clear();
    manifest.totals.blob_count = 0;
    manifest.totals.content_bytes = 0;
    entries.pop();
    write_raw_archive(&archive, &manifest, &entries);
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("1 missing, 0 extra"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let (mut manifest, mut entries) = read_raw_archive(&archive);
    let header = V2TableHeader {
        columns: manifest.tables[1].columns.clone(),
    };
    let mut table = serde_json::to_vec(&header).unwrap();
    table.push(b'\n');
    table.extend_from_slice(br#"["f1",null]"#);
    table.push(b'\n');
    entries[1].body = table;
    manifest.tables[1].byte_length = entries[1].body.len() as u64;
    manifest.tables[1].sha256 = sha256_bytes(&entries[1].body);
    manifest.totals.table_bytes = manifest.tables.iter().map(|table| table.byte_length).sum();
    write_raw_archive(&archive, &manifest, &entries);
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("0 missing, 1 extra"));
}

#[test]
fn unknown_tables_wrong_columns_duplicates_and_overflow_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let (mut manifest, entries) = read_raw_archive(&archive);
    manifest.tables[1].name = "unknown".to_string();
    manifest.tables[1].entry_path = "tables/01-unknown.jsonl".to_string();
    write_raw_archive(&archive, &manifest, &entries);
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("expected schema"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let (mut manifest, entries) = read_raw_archive(&archive);
    manifest.tables[1].columns[1] = "thumbnail_hash".to_string();
    write_raw_archive(&archive, &manifest, &entries);
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("schema order or columns"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let (mut manifest, entries) = read_raw_archive(&archive);
    manifest.blobs.push(manifest.blobs[0].clone());
    manifest.totals.blob_count = 2;
    manifest.totals.content_bytes *= 2;
    write_raw_archive(&archive, &manifest, &entries);
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("duplicated, or unsorted"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let (mut manifest, entries) = read_raw_archive(&archive);
    let mut overflow = manifest.blobs[0].clone();
    overflow.hash = if overflow.hash.starts_with('f') {
        "0".repeat(64)
    } else {
        "f".repeat(64)
    };
    overflow.entry_path = blob_entry_path(&overflow.hash).unwrap();
    overflow.byte_length = u64::MAX;
    manifest.blobs.push(overflow);
    manifest
        .blobs
        .sort_by(|left, right| left.hash.cmp(&right.hash));
    manifest.totals.blob_count = 2;
    write_raw_archive(&archive, &manifest, &entries);
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    assert!(error.to_string().contains("ustar entry limit"));
}

#[test]
fn arithmetic_overflow_helpers_fail_closed() {
    let error = tar_entry_size(u64::MAX).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    let error = expected_archive_size(
        &V2Manifest {
            format: FORMAT.to_string(),
            backup_id: "overflow".to_string(),
            created_at: "2026-07-16T00:00:00Z".to_string(),
            source_build: "test".to_string(),
            schema_fingerprint: "0".repeat(64),
            totals: V2Totals {
                table_count: 1,
                row_count: 0,
                table_bytes: u64::MAX,
                blob_count: 0,
                content_bytes: 0,
            },
            portable_integrity: None,
            tables: vec![V2TableDescriptor {
                order: 0,
                name: "table".to_string(),
                entry_path: "tables/00-table.jsonl".to_string(),
                columns: vec!["id".to_string()],
                row_count: 0,
                byte_length: u64::MAX,
                sha256: "0".repeat(64),
            }],
            blobs: vec![],
        },
        1,
        None,
    )
    .unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
}

#[test]
fn missing_or_extra_archive_entries_are_rejected_from_exact_size() {
    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let (manifest, mut entries) = read_raw_archive(&archive);
    entries.pop();
    write_raw_archive(&archive, &manifest, &entries);
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("archive length"));

    let root = tempfile::tempdir().unwrap();
    let (archive, schema, _) = create_fixture(root.path());
    let (manifest, mut entries) = read_raw_archive(&archive);
    entries.push(entries[0].clone());
    write_raw_archive(&archive, &manifest, &entries);
    let error = validate_archive(&archive, &schema, V2Limits::default()).unwrap_err();
    assert!(error.to_string().contains("archive length"));
}

#[test]
fn writer_refuses_missing_or_unreferenced_blob_sources() {
    let root = tempfile::tempdir().unwrap();
    let body = b"catalog body";
    let hash = sha256_bytes(body);
    let blob_path = root.path().join("blob");
    fs::write(&blob_path, body).unwrap();
    let tables = fixture_tables(&hash);
    let archive = root.path().join("missing.sxdbackup");
    let error = create_archive_atomic(
        &archive,
        root.path(),
        V2BuildInput {
            backup_id: "missing",
            created_at: "2026-07-16T00:00:00Z",
            source_build: "test",
            tables: &tables,
            blobs: &[],
        },
        V2Limits::default(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("1 missing, 0 extra"));
    assert!(!archive.exists());

    let empty_tables = vec![BackupTable {
        name: "files".to_string(),
        columns: vec!["id".to_string(), "content_hash".to_string()],
        rows: vec![vec![Value::String("f1".to_string()), Value::Null]],
    }];
    let archive = root.path().join("extra.sxdbackup");
    let error = create_archive_atomic(
        &archive,
        root.path(),
        V2BuildInput {
            backup_id: "extra",
            created_at: "2026-07-16T00:00:00Z",
            source_build: "test",
            tables: &empty_tables,
            blobs: &[V2BlobSource {
                hash,
                path: blob_path,
            }],
        },
        V2Limits::default(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("0 missing, 1 extra"));
    assert!(!archive.exists());
}

#[test]
fn archive_and_stage_files_are_private_and_partial_is_removed() {
    let root = tempfile::tempdir().unwrap();
    let (_archive, _, _) = create_fixture(root.path());
    assert!(!root.path().join("fixture.sxdbackup.partial").exists());
    assert!(!root.path().join(".fixture.v2-stage").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(_archive).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

fn mutate_nth_header(path: &Path, entry_index: usize, mutate: impl FnOnce(&mut [u8; 512])) {
    let offset = nth_header_offset(path, entry_index);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut header = [0u8; 512];
    file.read_exact(&mut header).unwrap();
    mutate(&mut header);
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&header).unwrap();
}

fn read_raw_archive(path: &Path) -> (V2Manifest, Vec<RawEntry>) {
    let mut file = File::open(path).unwrap();
    let manifest_header = read_tar_header(&mut file, "test manifest").unwrap();
    let mut manifest_bytes = vec![0u8; manifest_header.size as usize];
    file.read_exact(&mut manifest_bytes).unwrap();
    skip_tar_padding(&mut file, manifest_header.size, "test padding").unwrap();
    let mut manifest: V2Manifest = serde_json::from_slice(&manifest_bytes).unwrap();
    if manifest.portable_integrity.take().is_some() {
        let integrity_header = read_tar_header(&mut file, "test portable integrity").unwrap();
        assert_eq!(integrity_header.path, PORTABLE_INTEGRITY_PATH);
        file.seek(SeekFrom::Current(integrity_header.size as i64))
            .unwrap();
        skip_tar_padding(&mut file, integrity_header.size, "test padding").unwrap();
    }
    let entry_count = manifest.tables.len() + manifest.blobs.len();
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let header = read_tar_header(&mut file, "test entry").unwrap();
        let mut body = vec![0u8; header.size as usize];
        file.read_exact(&mut body).unwrap();
        skip_tar_padding(&mut file, header.size, "test padding").unwrap();
        entries.push(RawEntry {
            path: header.path,
            entry_type: header.entry_type,
            body,
        });
    }
    (manifest, entries)
}

fn write_raw_archive(path: &Path, manifest: &V2Manifest, entries: &[RawEntry]) {
    let mut file = File::create(path).unwrap();
    let manifest = encode_manifest(manifest, V2Limits::default()).unwrap();
    append_bytes_entry(&mut file, MANIFEST_PATH, &manifest).unwrap();
    for entry in entries {
        write_tar_header(
            &mut file,
            &entry.path,
            entry.body.len() as u64,
            entry.entry_type,
        )
        .unwrap();
        file.write_all(&entry.body).unwrap();
        write_tar_padding(&mut file, entry.body.len() as u64).unwrap();
    }
    file.write_all(&[0u8; TAR_TRAILER_BYTES as usize]).unwrap();
    file.sync_all().unwrap();
}

fn nth_entry_data_offset(path: &Path, entry_index: usize) -> u64 {
    nth_header_offset(path, entry_index) + 512
}

fn nth_header_offset(path: &Path, entry_index: usize) -> u64 {
    let mut file = File::open(path).unwrap();
    let mut offset = 0u64;
    for index in 0..=entry_index {
        file.seek(SeekFrom::Start(offset)).unwrap();
        let header = read_tar_header(&mut file, "test header").unwrap();
        if index == entry_index {
            return offset;
        }
        offset += tar_entry_size(header.size).unwrap();
    }
    unreachable!()
}

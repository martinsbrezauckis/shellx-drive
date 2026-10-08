use std::{fs, time::Duration};

use chrono::Utc;
use rusqlite::params;

use super::*;
use crate::{
    backup_v2::V2BlobDescriptor,
    model::{CreateFileRequest, FileKind},
    routes::backups::spawn_backup_worker,
};

use super::tests::{create_file_with_blob, test_state};

#[test]
fn verified_catalog_is_all_blob_byte_authority() {
    let root = tempfile::tempdir().unwrap();
    let data_dir = root.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();
    let storage = Storage::open(data_dir.join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Bytes", "owner@example.test")
        .unwrap();
    let body = b"file body";
    let content_hash = blob::put_blob(&data_dir, body).unwrap();
    let file_id = storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "file.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some(content_hash.clone()),
            body.len() as i64,
        )
        .unwrap()
        .0
        .id;
    let cover = b"cover bytes";
    let cover_hash = blob::put_blob(&data_dir, cover).unwrap();
    let folder_id = storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "covered-folder".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
            0,
        )
        .unwrap()
        .0
        .id;
    storage
        .set_folder_cover(&folder_id, &cover_hash, cover.len() as i64)
        .unwrap();
    let thumbnail = b"thumbnail bytes";
    let thumbnail_hash = blob::put_blob(&data_dir, thumbnail).unwrap();
    let now = Utc::now().to_rfc3339();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO file_previews (file_id, workspace_id, revision, kind, content,
             thumbnail_hash, thumbnail_content_type, thumbnail_bytes, status, updated_at)
             VALUES (?1, ?2, 1, 'image', '', ?3, 'image/png', ?4, 'ready', ?5)",
            params![
                file_id,
                workspace.id,
                thumbnail_hash,
                thumbnail.len() as i64,
                now
            ],
        )
        .unwrap();
    }
    let mut catalog = [
        (content_hash, body.len()),
        (cover_hash, cover.len()),
        (thumbnail_hash, thumbnail.len()),
    ]
    .into_iter()
    .map(|(hash, bytes)| V2BlobDescriptor {
        hash,
        entry_path: String::new(),
        byte_length: bytes as u64,
    })
    .collect::<Vec<_>>();
    catalog.sort_by(|left, right| left.hash.cmp(&right.hash));

    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        restore_accounting::validate_in_tx(&tx, &catalog, false).unwrap();
    }
    for (sql, field, target_id) in [
        (
            "UPDATE files SET content_bytes = content_bytes + 1 WHERE id = ?1",
            "files.content_bytes",
            &file_id,
        ),
        (
            "UPDATE file_revisions SET content_bytes = content_bytes + 1 WHERE file_id = ?1",
            "file_revisions.content_bytes",
            &file_id,
        ),
        (
            "UPDATE file_previews SET thumbnail_bytes = thumbnail_bytes + 1 WHERE file_id = ?1",
            "file_previews.thumbnail_bytes",
            &file_id,
        ),
        (
            "UPDATE files SET cover_bytes = cover_bytes + 1 WHERE id = ?1",
            "files.cover_bytes",
            &folder_id,
        ),
    ] {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute(sql, [target_id]).unwrap();
        let error = restore_accounting::validate_in_tx(&tx, &catalog, false).unwrap_err();
        assert!(error.to_string().contains(field), "{error}");
    }

    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute(
        "UPDATE files SET cover_bytes = 0 WHERE id = ?1",
        [&folder_id],
    )
    .unwrap();
    restore_accounting::validate_in_tx(&tx, &catalog, true).unwrap();
    let reconciled: i64 = tx
        .query_row(
            "SELECT cover_bytes FROM files WHERE id = ?1",
            [&folder_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reconciled, cover.len() as i64);
}

#[tokio::test]
async fn v2_restore_rejects_forged_content_bytes_before_commit() {
    let source_root = tempfile::tempdir().unwrap();
    let source_data_dir = source_root.path().join("source-data");
    fs::create_dir_all(&source_data_dir).unwrap();
    let source = Storage::open(source_data_dir.join("drive.db")).unwrap();
    source.migrate().unwrap();
    let body = b"catalog-authoritative body";
    let (file_id, hash) = create_file_with_blob(&source, &source_data_dir, "forged.bin", body);
    source
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE files SET content_bytes = 1 WHERE id = ?1",
            [&file_id],
        )
        .unwrap();
    let backup_id = "forged-byte-authority";
    let archive = source_root.path().join(format!("{backup_id}.sxdbackup"));
    source
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
        .unwrap();

    let target_root = tempfile::tempdir().unwrap();
    let state = test_state(target_root.path().join("target-data"));
    let target_data_dir = state.data_dir();
    fs::create_dir_all(target_data_dir.join("backups")).unwrap();
    fs::copy(
        archive,
        target_data_dir
            .join("backups")
            .join(format!("{backup_id}.sxdbackup")),
    )
    .unwrap();
    let restore = state
        .storage
        .enqueue_scheduled_backup_job("restore", backup_id, "system@local")
        .unwrap();
    let worker = spawn_backup_worker(state.clone());
    for _ in 0..160 {
        if state
            .storage
            .get_backup_job(&restore.id)
            .unwrap()
            .unwrap()
            .status
            == "failed"
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    worker.abort();

    let job = state.storage.get_backup_job(&restore.id).unwrap().unwrap();
    assert_eq!(job.status, "failed");
    assert!(job
        .last_error
        .as_deref()
        .is_some_and(|error| error.contains("files.content_bytes")));
    let file_count: i64 = state
        .storage
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
        .unwrap();
    assert_eq!(file_count, 0);
    assert!(!blob::blob_file_path(&target_data_dir, &hash)
        .unwrap()
        .exists());
}

use chrono::{Duration, Utc};
use rusqlite::params;

use crate::{
    auth::{Actor, AuthMode, DriveCredential},
    model::{
        ContentWrite, CreateFileRequest, DriveFile, FileKind, NullableI64Patch,
        UpdateWorkspacePolicyRequest,
    },
};

use super::*;

fn storage() -> (tempfile::TempDir, Storage) {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    (directory, storage)
}

fn file(storage: &Storage, workspace: &str, name: &str) -> DriveFile {
    storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace.to_string(),
                parent_id: None,
                name: name.to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some("a".repeat(64)),
            1,
        )
        .unwrap()
        .0
}

fn record(storage: &Storage, file: &DriveFile) -> DeltaWriteStats {
    storage
        .record_delta_sync_write(
            &file.id,
            &file.workspace_id,
            "fixture@example.test",
            file.revision - 1,
            file.revision,
            1,
            1,
            0,
            1,
            1,
            &"a".repeat(64),
        )
        .unwrap()
}

fn assert_bounds(storage: &Storage) {
    let conn = storage.conn.lock().unwrap();
    for (query, maximum) in [
        ("SELECT COUNT(*) FROM delta_sync_writes", MAX_DELTA_STATS_GLOBAL),
        ("SELECT COALESCE(MAX(n), 0) FROM (SELECT COUNT(*) n FROM delta_sync_writes GROUP BY file_id)", MAX_DELTA_STATS_PER_FILE),
        ("SELECT COALESCE(MAX(n), 0) FROM (SELECT COUNT(*) n FROM delta_sync_writes GROUP BY workspace_id)", MAX_DELTA_STATS_PER_WORKSPACE),
    ] {
        assert!(conn.query_row(query, [], |row| row.get::<_, i64>(0)).unwrap() <= maximum);
    }
}

#[test]
fn tiny_authorized_writes_and_revision_pruning_keep_only_bounded_statistics() {
    let (_directory, storage) = storage();
    let email = "delta-owner@example.test";
    let (account, workspace, _, _) = storage
        .bootstrap_auth_account_with_workspace(email, "stored-password-hash", "Delta", "open")
        .unwrap();
    storage
        .record_auth_session(
            "delta-source",
            email,
            "local-password",
            &account.user_id,
            "delta-source-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let actor = Actor {
        email: email.to_string(),
        is_admin: false,
        auth_mode: AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    };
    let source = DriveCredential::UserSession("delta-source".to_string());
    storage
        .update_workspace_policy(
            &workspace.id,
            UpdateWorkspacePolicyRequest {
                quota_bytes: NullableI64Patch::Missing,
                public_links_enabled: None,
                link_password_required: None,
                allow_never_expire: None,
                max_link_ttl_seconds: None,
                drop_password_required: None,
                max_drop_ttl_seconds: None,
                trash_retention_days: None,
                revision_retention_days: Some(0),
            },
            &actor,
            &source,
        )
        .unwrap();
    let mut current = file(&storage, &workspace.id, "tiny.txt");
    let mut latest = String::new();
    for index in 0..MAX_DELTA_STATS_PER_FILE + 8 {
        let hash = if index % 2 == 0 { "b" } else { "a" }.repeat(64);
        current = match storage
            .put_content_authorized(&current.id, current.revision, &hash, 1, &actor, &source)
            .unwrap()
        {
            ContentWrite::Updated { file, .. } => file,
            ContentWrite::Conflict(_) => panic!("current tiny write unexpectedly conflicted"),
        };
        latest = record(&storage, &current).id;
        storage
            .prune_file_revisions_authorized(&current.id, &actor, &source)
            .unwrap();
    }
    assert_eq!(storage.list_file_revisions(&current.id).unwrap().len(), 1);
    let conn = storage.conn.lock().unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM delta_sync_writes", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        MAX_DELTA_STATS_PER_FILE
    );
    assert!(conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM delta_sync_writes WHERE id = ?1)",
            [latest],
            |row| row.get::<_, bool>(0)
        )
        .unwrap());
}

/// Seed historical rows directly, as an older release or restore could have
/// done. Each timestamp and id is deterministic so latest-row retention has
/// an independent oracle. No mocked quota decision is used.
fn seed_history(
    storage: &Storage,
    workspaces: i64,
    files_per_workspace: i64,
    rows_per_file: i64,
) -> Vec<DriveFile> {
    let mut files = Vec::new();
    for workspace_index in 0..workspaces {
        let workspace = storage
            .create_workspace(
                &format!("History {workspace_index}"),
                "fixture@example.test",
            )
            .unwrap()
            .0;
        for file_index in 0..files_per_workspace {
            files.push(file(storage, &workspace.id, &format!("{file_index}.txt")));
        }
    }
    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    {
        let mut insert = tx.prepare(
            "INSERT INTO delta_sync_writes (id, file_id, workspace_id, actor_email, base_revision,
                new_revision, chunk_size, chunks_total, chunks_reused, uploaded_bytes,
                reconstructed_bytes, content_sha256, created_at)
             VALUES (?1, ?2, ?3, 'fixture', 1, 2, 1, 1, 0, 1, 1, 'fixture', ?4)",
        ).unwrap();
        for (file_index, file) in files.iter().enumerate() {
            for row_index in 0..rows_per_file {
                insert
                    .execute(params![
                        format!("legacy-{file_index:03}-{row_index:05}"),
                        &file.id,
                        &file.workspace_id,
                        format!("2000-01-01T00:00:00.{row_index:09}Z")
                    ])
                    .unwrap();
            }
        }
    }
    tx.commit().unwrap();
    files
}

#[test]
fn migration_reconciles_oversized_file_workspace_and_global_history() {
    let (_directory, storage) = storage();
    let files = seed_history(&storage, 6, 10, MAX_DELTA_STATS_PER_FILE + 2);
    storage.migrate().unwrap();
    assert_bounds(&storage);
    let conn = storage.conn.lock().unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM delta_sync_writes", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        MAX_DELTA_STATS_GLOBAL
    );
    assert!(!conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM delta_sync_writes WHERE id = 'legacy-059-00000')",
            [],
            |row| row.get::<_, bool>(0)
        )
        .unwrap());
    assert!(conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM delta_sync_writes WHERE id = 'legacy-059-00513')",
            [],
            |row| row.get::<_, bool>(0)
        )
        .unwrap());
    drop(conn);
    let latest = record(&storage, &files[0]);
    assert_bounds(&storage);
    assert!(storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM delta_sync_writes WHERE id = ?1)",
            [&latest.id],
            |row| row.get::<_, bool>(0)
        )
        .unwrap());
}

#[test]
fn insertion_bounds_all_its_partitions_without_losing_the_current_statistic() {
    let (_directory, storage) = storage();
    let files = seed_history(&storage, 4, 8, MAX_DELTA_STATS_PER_FILE);
    // A saturated but valid file, workspace, and global history. Exercise
    // each scope independently by inserting into an existing file, a new
    // file in the same workspace, then a file in a new workspace.
    let target = files.last().unwrap();
    let latest = record(&storage, target);
    assert_bounds(&storage);
    assert!(storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM delta_sync_writes WHERE id = ?1)",
            [&latest.id],
            |row| row.get::<_, bool>(0)
        )
        .unwrap());
    let new_file = file(&storage, &target.workspace_id, "new-file.txt");
    record(&storage, &new_file);
    assert_bounds(&storage);
    let new_workspace = storage
        .create_workspace("New statistics workspace", "fixture@example.test")
        .unwrap()
        .0;
    record(
        &storage,
        &file(&storage, &new_workspace.id, "new-workspace.txt"),
    );
    assert_bounds(&storage);
}

#[test]
fn failed_telemetry_persistence_does_not_turn_a_committed_write_into_an_error() {
    let (_directory, storage) = storage();
    let workspace = storage
        .create_workspace("Telemetry failure", "fixture@example.test")
        .unwrap()
        .0;
    let original = file(&storage, &workspace.id, "committed.txt");
    let current = match storage
        .put_content(&original.id, original.revision, &"b".repeat(64), 1)
        .unwrap()
    {
        ContentWrite::Updated { file, .. } => file,
        ContentWrite::Conflict(_) => panic!("current write unexpectedly conflicted"),
    };
    storage
        .conn
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fixture_reject_statistics BEFORE INSERT ON delta_sync_writes
         BEGIN SELECT RAISE(ABORT, 'fixture telemetry refusal'); END;",
        )
        .unwrap();
    let stats = record(&storage, &current);
    assert_eq!(stats.new_revision, current.revision);
    assert_eq!(
        storage.get_file(&original.id).unwrap().unwrap().revision,
        current.revision
    );
    assert_eq!(
        storage
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM delta_sync_writes", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

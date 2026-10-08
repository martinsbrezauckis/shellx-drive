use rusqlite::{params, TransactionBehavior};

use super::*;
use crate::{model::CreateFileRequest, storage::Storage};

mod recovery;
mod recovery_bounds;
mod restore;
mod search_revision;

fn create_file(storage: &Storage, workspace_id: &str, name: &str) -> DriveFile {
    storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id: None,
                name: name.to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0
}

fn clear_jobs(storage: &Storage) {
    storage
        .conn
        .lock()
        .unwrap()
        .execute("DELETE FROM background_jobs", [])
        .unwrap();
}

fn enqueue_with_limits(
    storage: &Storage,
    file: &DriveFile,
    limits: PendingJobLimits,
) -> BackgroundJobAdmission {
    let mut conn = storage.conn.lock().unwrap();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let outcome = enqueue_file_background_jobs_in_tx_with_limits(&tx, file, limits).unwrap();
    tx.commit().unwrap();
    outcome
}

#[test]
fn pending_admission_is_atomic_and_partitioned_by_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace_a, _, _) = storage
        .create_workspace("Derived queue A", "a@example.test")
        .unwrap();
    let (workspace_b, _, _) = storage
        .create_workspace("Derived queue B", "b@example.test")
        .unwrap();
    let (workspace_c, _, _) = storage
        .create_workspace("Derived queue C", "c@example.test")
        .unwrap();
    let mut a_first = create_file(&storage, &workspace_a.id, "a-first.txt");
    let mut a_second = create_file(&storage, &workspace_a.id, "a-second.txt");
    let mut b_first = create_file(&storage, &workspace_b.id, "b-first.txt");
    let mut c_first = create_file(&storage, &workspace_c.id, "c-first.txt");
    clear_jobs(&storage);
    for file in [&mut a_first, &mut a_second, &mut b_first, &mut c_first] {
        file.size_bytes = Some(10);
    }
    let limits = PendingJobLimits {
        global_count: 4,
        workspace_count: 2,
        global_bytes: 40,
        workspace_bytes: 20,
    };

    assert_eq!(
        enqueue_with_limits(&storage, &a_first, limits),
        BackgroundJobAdmission::Queued
    );
    // The second file cannot partially consume A's two-job quota.
    assert_eq!(
        enqueue_with_limits(&storage, &a_second, limits),
        BackgroundJobAdmission::DroppedAtCapacity
    );
    assert_eq!(
        storage
            .list_background_jobs()
            .unwrap()
            .iter()
            .filter(|job| job.file_id.as_deref() == Some(a_second.id.as_str()))
            .count(),
        0
    );

    assert_eq!(
        enqueue_with_limits(&storage, &b_first, limits),
        BackgroundJobAdmission::Queued
    );
    // A third workspace is rejected by the global count and byte bounds,
    // again without publishing one of its two products.
    assert_eq!(
        enqueue_with_limits(&storage, &c_first, limits),
        BackgroundJobAdmission::DroppedAtCapacity
    );
    assert_eq!(storage.background_job_totals().unwrap().queued, 4);

    // A larger later revision may not leave the old lower-byte estimate in
    // the queue. Saturation removes this file's stale pair deterministically.
    a_first.size_bytes = Some(20);
    assert_eq!(
        enqueue_with_limits(&storage, &a_first, limits),
        BackgroundJobAdmission::DroppedAtCapacity
    );
    assert_eq!(
        storage
            .list_background_jobs()
            .unwrap()
            .iter()
            .filter(|job| job.file_id.as_deref() == Some(a_first.id.as_str()))
            .count(),
        0
    );
    assert_eq!(storage.background_job_totals().unwrap().queued, 2);
}

#[test]
fn scheduler_interleaves_oldest_pending_job_per_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace_a, _, _) = storage
        .create_workspace("Fair queue A", "a@example.test")
        .unwrap();
    let (workspace_b, _, _) = storage
        .create_workspace("Fair queue B", "b@example.test")
        .unwrap();
    let (workspace_c, _, _) = storage
        .create_workspace("Fair queue C", "c@example.test")
        .unwrap();
    let a = create_file(&storage, &workspace_a.id, "a.txt");
    let b = create_file(&storage, &workspace_b.id, "b.txt");
    let c = create_file(&storage, &workspace_c.id, "c.txt");
    clear_jobs(&storage);
    for file in [&a, &b, &c] {
        assert_eq!(
            enqueue_with_limits(&storage, file, DEFAULT_PENDING_JOB_LIMITS),
            BackgroundJobAdmission::Queued
        );
    }

    let conn = storage.conn.lock().unwrap();
    for (file, first, second) in [
        (&a, "2026-01-01T00:00:01Z", "2026-01-01T00:00:04Z"),
        (&b, "2026-01-01T00:00:02Z", "2026-01-01T00:00:05Z"),
        (&c, "2026-01-01T00:00:03Z", "2026-01-01T00:00:06Z"),
    ] {
        conn.execute(
            "UPDATE background_jobs
             SET created_at = CASE kind
                WHEN 'search_index' THEN ?1 ELSE ?2 END,
                 updated_at = CASE kind
                WHEN 'search_index' THEN ?1 ELSE ?2 END
             WHERE file_id = ?3",
            params![first, second, &file.id],
        )
        .unwrap();
    }
    drop(conn);

    let queued = storage.queued_background_jobs().unwrap();
    let scheduled_file_ids = queued
        .iter()
        .map(|job| job.file_id.as_deref().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        scheduled_file_ids,
        vec![
            a.id.as_str(),
            b.id.as_str(),
            c.id.as_str(),
            a.id.as_str(),
            b.id.as_str(),
            c.id.as_str(),
        ]
    );
}

#[test]
fn migration_trims_an_oversized_legacy_workspace_backlog_by_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Legacy derived backlog", "owner@example.test")
        .unwrap();
    let files = (0..17)
        .map(|index| create_file(&storage, &workspace.id, &format!("{index}.txt")))
        .collect::<Vec<_>>();
    clear_jobs(&storage);

    let conn = storage.conn.lock().unwrap();
    for (index, file) in files.iter().enumerate() {
        let timestamp = format!("2026-01-01T00:00:{index:02}Z");
        conn.execute(
            "UPDATE files SET content_bytes = ?1 WHERE id = ?2",
            params![MAX_DERIVED_INPUT_BYTES as i64, &file.id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO background_jobs
                (id, kind, status, workspace_id, file_id, estimated_bytes,
                 attempts, last_error, created_at, updated_at, started_at, finished_at)
             VALUES (?1, 'legacy', 'queued', ?2, ?3, 1, 0, NULL, ?4, ?4, NULL, NULL)",
            params![
                format!("legacy-{}", file.id),
                &workspace.id,
                &file.id,
                timestamp
            ],
        )
        .unwrap();
    }
    drop(conn);

    storage.migrate().unwrap();
    let queued = storage
        .queued_background_jobs()
        .unwrap()
        .into_iter()
        .filter(|job| {
            job.status == "queued" && job.workspace_id.as_deref() == Some(workspace.id.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(queued.len(), 16);
    assert_eq!(
        queued
            .iter()
            .map(|job| job.file_id.as_deref().unwrap())
            .collect::<Vec<_>>(),
        files[..16]
            .iter()
            .map(|file| file.id.as_str())
            .collect::<Vec<_>>()
    );
}

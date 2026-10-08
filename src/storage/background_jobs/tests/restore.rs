use super::*;

#[test]
fn restored_jobs_are_subject_checked_reestimated_and_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Restored derived backlog", "owner@example.test")
        .unwrap();
    let files = (0..18)
        .map(|index| create_file(&storage, &workspace.id, &format!("{index}.txt")))
        .collect::<Vec<_>>();
    clear_jobs(&storage);

    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    for (index, file) in files.iter().enumerate() {
        let timestamp = format!("2026-01-01T00:00:{index:02}Z");
        tx.execute(
            "UPDATE files SET content_bytes = ?1 WHERE id = ?2",
            params![MAX_DERIVED_INPUT_BYTES as i64, &file.id],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO background_jobs
                (id, kind, status, workspace_id, file_id, estimated_bytes,
                 attempts, last_error, created_at, updated_at, started_at, finished_at)
             VALUES (?1, 'search_index', 'queued', ?2, ?3, -99, 8, 'archive',
                     ?4, ?4, ?4, ?4)",
            params![
                format!("restored-{}", file.id),
                &workspace.id,
                &file.id,
                timestamp
            ],
        )
        .unwrap();
    }
    tx.execute(
        "INSERT INTO background_jobs
            (id, kind, status, workspace_id, file_id, estimated_bytes,
             attempts, created_at, updated_at)
         VALUES ('unsupported', 'future_kind', 'queued', ?1, ?2, 1, 0, ?3, ?3)",
        params![&workspace.id, &files[0].id, "2026-01-01T00:01:00Z"],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO background_jobs
            (id, kind, status, workspace_id, file_id, estimated_bytes,
             attempts, created_at, updated_at, started_at)
         VALUES ('stale-running', 'preview_text', 'running', ?1, ?2, 1, 1, ?3, ?3, ?3)",
        params![&workspace.id, &files[0].id, "2026-01-01T00:01:01Z"],
    )
    .unwrap();

    normalize_restored_jobs(&tx).unwrap();
    tx.commit().unwrap();
    drop(conn);

    let jobs = storage.list_background_jobs().unwrap();
    assert_eq!(jobs.len(), 16);
    assert!(jobs.iter().all(|job| {
        job.kind == "search_index"
            && job.status == "queued"
            && job.attempts == 0
            && job.last_error.is_none()
    }));
    let conn = storage.conn.lock().unwrap();
    let invalid_estimate_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM background_jobs WHERE estimated_bytes != ?1",
            params![MAX_DERIVED_INPUT_BYTES as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(invalid_estimate_count, 0);
}

#[test]
fn legacy_restore_safely_readmits_supported_pending_work() {
    let source_dir = tempfile::tempdir().unwrap();
    let source = Storage::open(source_dir.path().join("drive.db")).unwrap();
    source.migrate().unwrap();
    let (workspace, _, _) = source
        .create_workspace("Legacy queue source", "owner@example.test")
        .unwrap();
    let file = create_file(&source, &workspace.id, "pending.txt");
    assert!(source.background_job_totals().unwrap().queued > 0);
    let tables = source.export_backup_tables().unwrap();

    let target_dir = tempfile::tempdir().unwrap();
    let target = Storage::open(target_dir.path().join("drive.db")).unwrap();
    target.migrate().unwrap();
    target.restore_backup_tables(&tables).unwrap();

    let totals = target.background_job_totals().unwrap();
    assert_eq!(totals.queued, 2);
    assert_eq!(
        totals.running + totals.succeeded + totals.failed + totals.skipped,
        0
    );
    let jobs = target.list_background_jobs().unwrap();
    assert_eq!(jobs.len(), 2);
    assert!(jobs.iter().all(|job| {
        job.status == "queued"
            && job.attempts == 0
            && job.last_error.is_none()
            && matches!(job.kind.as_str(), "search_index" | "preview_text")
    }));
    assert!(target.get_file(&file.id).unwrap().is_some());
}

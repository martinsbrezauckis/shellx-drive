use super::*;

#[test]
fn crash_recovery_rebounds_pending_work_and_prunes_terminal_history() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Recovery bounds", "owner@example.test")
        .unwrap();
    let file = create_file(&storage, &workspace.id, "recovery.txt");
    clear_jobs(&storage);

    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    for index in 0..MAX_PENDING_BACKGROUND_JOBS {
        tx.execute(
            "INSERT INTO background_jobs
                (id, kind, status, workspace_id, file_id, estimated_bytes,
                 attempts, created_at, updated_at)
             VALUES (?1, 'search_index', 'queued', ?2, NULL, 1, 0, ?3, ?3)",
            params![
                format!("queued-{index}"),
                &workspace.id,
                "2026-01-01T00:00:00Z"
            ],
        )
        .unwrap();
    }
    for (id, kind, attempts) in [
        ("requeue-search", "search_index", 1),
        ("requeue-preview", "preview_text", 1),
        ("capped-search", "search_index", MAX_BACKGROUND_JOB_ATTEMPTS),
        (
            "capped-preview",
            "preview_text",
            MAX_BACKGROUND_JOB_ATTEMPTS,
        ),
    ] {
        tx.execute(
            "INSERT INTO background_jobs
                (id, kind, status, workspace_id, file_id, estimated_bytes,
                 attempts, created_at, updated_at, started_at)
             VALUES (?1, ?2, 'running', ?3, ?4, 1, ?5, ?6, ?6, ?6)",
            params![
                id,
                kind,
                &workspace.id,
                &file.id,
                attempts,
                "2026-01-02T00:00:00Z"
            ],
        )
        .unwrap();
    }
    for index in 0..1_000 {
        tx.execute(
            "INSERT INTO background_jobs
                (id, kind, status, workspace_id, estimated_bytes, attempts,
                 created_at, updated_at, finished_at)
             VALUES (?1, 'search_index', 'succeeded', ?2, 1, 1, ?3, ?3, ?3)",
            params![
                format!("terminal-{index}"),
                &workspace.id,
                "2026-01-01T00:00:00Z"
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    drop(conn);

    assert_eq!(storage.recover_running_background_jobs().unwrap(), (2, 2));
    let conn = storage.conn.lock().unwrap();
    let (count, bytes): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(estimated_bytes), 0)
             FROM background_jobs WHERE status = 'queued'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(count <= MAX_PENDING_BACKGROUND_JOBS);
    assert!(bytes <= MAX_PENDING_BACKGROUND_JOB_BYTES);
    let (workspace_count, workspace_bytes): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(estimated_bytes), 0)
             FROM background_jobs WHERE status = 'queued' AND workspace_id = ?1",
            params![&workspace.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(workspace_count <= MAX_PENDING_BACKGROUND_JOBS_PER_WORKSPACE);
    assert!(workspace_bytes <= MAX_PENDING_BACKGROUND_JOB_BYTES_PER_WORKSPACE);
    let terminal: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM background_jobs
             WHERE workspace_id = ?1 AND status IN ('succeeded', 'failed', 'skipped')",
            params![&workspace.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(terminal, 1_000);
}

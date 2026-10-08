use super::tests::test_state;

#[test]
fn create_publication_success_and_receipt_commit_atomically() {
    let root = tempfile::tempdir().unwrap();
    let state = test_state(root.path().join("atomic-publication"));
    let backup_id = "atomic-publication";
    let queued = state
        .storage
        .enqueue_scheduled_backup_job("create", backup_id, "system@local")
        .unwrap();
    state.storage.claim_backup_job(&queued.id).unwrap().unwrap();
    {
        let conn = state.storage.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TEMP TRIGGER reject_final_create_receipt
             BEFORE INSERT ON receipts
             WHEN NEW.kind = 'backup.create'
             BEGIN
               SELECT RAISE(ABORT, 'fixture receipt failure');
             END;",
        )
        .unwrap();
    }

    assert!(state
        .storage
        .finalize_v2_backup_create_publication(&queued.id, &"a".repeat(64))
        .is_err());
    assert_eq!(
        state
            .storage
            .get_backup_job(&queued.id)
            .unwrap()
            .unwrap()
            .status,
        "running"
    );
    let conn = state.storage.conn.lock().unwrap();
    let receipts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM receipts WHERE kind = 'backup.create' AND target_id = ?1",
            [backup_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(receipts, 0);
}

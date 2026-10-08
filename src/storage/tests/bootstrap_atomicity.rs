use super::*;

#[test]
fn bootstrap_wizard_rolls_back_account_when_workspace_creation_fails() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_bootstrap_workspace
         BEFORE INSERT ON workspaces
         BEGIN SELECT RAISE(ABORT, 'workspace insert rejected by test'); END;",
        )
        .unwrap();

    assert!(storage
        .bootstrap_auth_account_with_workspace(
            "first-admin@example.test",
            "stored-password-hash",
            "Personal Drive",
            "open",
        )
        .is_err());
    assert_eq!(storage.auth_account_count().unwrap(), 0);
    let conn = storage.conn.lock().unwrap();
    for table in ["users", "workspaces", "workspace_members", "receipts"] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must roll back with the failed wizard");
    }
    conn.execute_batch("DROP TRIGGER reject_bootstrap_workspace;")
        .unwrap();
    drop(conn);

    let (account, workspace, owner, receipt) = storage
        .bootstrap_auth_account_with_workspace(
            "first-admin@example.test",
            "stored-password-hash",
            "Personal Drive",
            "open",
        )
        .unwrap();
    assert!(account.is_admin);
    assert_eq!(account.user_id, owner.id);
    assert_eq!(workspace.name, "Personal Drive");
    assert_eq!(receipt.kind, "workspace.create");
    assert_eq!(
        storage
            .list_receipts()
            .unwrap()
            .into_iter()
            .map(|receipt| receipt.kind)
            .collect::<Vec<_>>(),
        vec!["auth.account.create", "workspace.create"]
    );
}

use super::{assert_ledger_matches_rebuild, storage};

#[test]
fn workspace_notification_pruning_retains_the_limit_and_exact_ledger() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Notification pruning", "owner@example.test")
        .unwrap();
    for index in 0..=1_000 {
        storage
            .create_notification(
                "recipient@example.test",
                "comment_created",
                "Comment notice",
                &format!("notice {index}"),
                Some(&workspace.id),
                None,
                Some("comment"),
                Some("comment-id"),
            )
            .unwrap();
    }
    let conn = storage.conn.lock().unwrap();
    let retained: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications WHERE recipient_email = 'recipient@example.test'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(conn);
    assert_eq!(retained, 100);
    assert_ledger_matches_rebuild(&storage, &workspace.id);
}

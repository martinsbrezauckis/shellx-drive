use rusqlite::params;

use crate::error::ApiError;

use super::super::Storage;
use super::*;

fn storage() -> (tempfile::TempDir, Storage) {
    let data = tempfile::tempdir().unwrap();
    let storage = Storage::open(data.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    (data, storage)
}

#[test]
fn metadata_projection_enforces_shape_and_serialized_byte_limits() {
    let projection = project_file_metadata_storage(
        vec![
            " Beta ".to_string(),
            "alpha".to_string(),
            "alpha".to_string(),
        ],
        &serde_json::json!({"phase": ["draft", true]}),
    )
    .unwrap();
    assert_eq!(projection.labels, ["alpha", "beta"]);
    assert_eq!(
        projection.usage.file_metadata_bytes,
        projection.usage.metadata_fts_projection_bytes
    );
    let deeply_nested = (0..=MAX_FILE_METADATA_JSON_DEPTH).fold(
        serde_json::json!(null),
        |child, _| serde_json::json!({"next": child}),
    );
    assert!(matches!(
        validate_auxiliary_metadata_json(&deeply_nested),
        Err(ApiError::PayloadTooLarge(_))
    ));
}

#[test]
fn notice_snippets_remain_within_utf8_boundary() {
    let snippet = bounded_notice_snippet_with_limit("  \u{1f642}\u{1f642}\u{1f642}  ", 8);
    assert_eq!(snippet, "\u{1f642}…");
    assert!(snippet.len() <= 8);
}

#[test]
fn reconciliation_accounts_each_workspace_category_without_backup_authority() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Auxiliary", "owner@example.test")
        .unwrap();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO files (
                id, workspace_id, parent_id, name, kind, revision, trashed,
                content_hash, content_bytes, created_at, updated_at, cover_hash, cover_bytes
             ) VALUES ('file-1', ?1, NULL, 'File', 'file', 1, 0, NULL, 0, 'now', 'now', NULL, 0)",
            params![&workspace.id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO file_metadata (file_id, labels_json, custom_json, updated_at)
             VALUES ('file-1', '[]', '{}', 'now')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO file_search_fts (file_id, workspace_id, name, labels, metadata, content)
             VALUES ('file-1', ?1, 'File', '[]', '{}', '')",
            params![&workspace.id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO comments (id, file_id, author_email, body, resolved, created_at, updated_at)
             VALUES ('comment-1', 'file-1', 'owner@example.test', 'a', 0, 'now', 'now')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO comment_replies (id, comment_id, author_email, body, created_at, updated_at)
             VALUES ('reply-1', 'comment-1', 'owner@example.test', 'bc', 'now', 'now')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO notifications (
                id, recipient_email, workspace_id, kind, title, body, created_at
             ) VALUES ('notice-1', 'owner@example.test', ?1, 'test', 'd', 'ef', 'now')",
            params![&workspace.id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO email_outbox (
                id, kind, status, recipient_email, subject, body_text, attempts,
                created_at, updated_at, workspace_id
             ) VALUES ('email-1', 'test', 'queued', 'owner@example.test', 'g', 'hij', 0,
                       'now', 'now', ?1)",
            params![&workspace.id],
        )
        .unwrap();
    }
    storage.rebuild_workspace_auxiliary_storage_usage().unwrap();
    let usage = storage
        .workspace_auxiliary_storage_usage(&workspace.id)
        .unwrap();
    assert_eq!(usage.file_metadata_bytes, 4);
    assert_eq!(usage.metadata_fts_projection_bytes, 4);
    assert_eq!(usage.comment_reply_body_bytes, 3);
    assert_eq!(usage.notification_bytes, 3);
    assert_eq!(usage.email_outbox_bytes, 4);
    assert_eq!(usage.total_bytes, 18);
}

#[test]
fn over_limit_ledger_allows_reduction_but_rejects_growth() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Auxiliary", "owner@example.test")
        .unwrap();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM workspace_auxiliary_usage WHERE workspace_id = ?1",
            params![&workspace.id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspace_auxiliary_usage (
                workspace_id, file_metadata_bytes, metadata_fts_projection_bytes,
                comment_reply_body_bytes, notification_bytes, email_outbox_bytes, updated_at
             ) VALUES (?1, 0, 0, 0, ?2, 0, 'now')",
            params![
                &workspace.id,
                DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES + 2
            ],
        )
        .unwrap();
    }
    let reduced = storage
        .ensure_workspace_auxiliary_storage_delta_fits(
            &workspace.id,
            WorkspaceAuxiliaryStorageDelta {
                notification_bytes: -1,
                ..WorkspaceAuxiliaryStorageDelta::default()
            },
        )
        .unwrap();
    assert!(reduced.over_limit);
    assert!(matches!(
        storage.ensure_workspace_auxiliary_storage_delta_fits(
            &workspace.id,
            WorkspaceAuxiliaryStorageDelta {
                notification_bytes: 1,
                ..WorkspaceAuxiliaryStorageDelta::default()
            },
        ),
        Err(ApiError::PayloadTooLarge(_))
    ));
}

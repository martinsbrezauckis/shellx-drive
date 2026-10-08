use chrono::Utc;
use rusqlite::{params, Connection};

/// This is public inside storage so a restore transaction can rebuild after it
/// restores authoritative rows and the derived FTS projection.
pub(crate) fn rebuild_workspace_auxiliary_storage_usage_in_tx(
    conn: &Connection,
) -> rusqlite::Result<()> {
    let updated_at = Utc::now().to_rfc3339();
    conn.execute("DELETE FROM workspace_auxiliary_usage", [])?;
    conn.execute(
        "DELETE FROM workspace_auxiliary_metadata_fts_projection",
        [],
    )?;
    conn.execute(
        "INSERT INTO workspace_auxiliary_metadata_fts_projection (
            file_id, workspace_id, projection_bytes
         )
         SELECT files.id,
                files.workspace_id,
                COALESCE(
                    (SELECT LENGTH(CAST(metadata.labels_json AS BLOB))
                            + LENGTH(CAST(metadata.custom_json AS BLOB))
                     FROM file_metadata metadata WHERE metadata.file_id = files.id),
                    4
                )
         FROM files",
        [],
    )?;
    conn.execute(
        "INSERT INTO workspace_auxiliary_usage (
            workspace_id, file_metadata_bytes, metadata_fts_projection_bytes,
            comment_reply_body_bytes, notification_bytes, email_outbox_bytes, updated_at
         )
         SELECT workspaces.id,
                COALESCE((
                    SELECT SUM(LENGTH(CAST(metadata.labels_json AS BLOB))
                               + LENGTH(CAST(metadata.custom_json AS BLOB)))
                    FROM file_metadata metadata
                    JOIN files ON files.id = metadata.file_id
                    WHERE files.workspace_id = workspaces.id
                ), 0),
                COALESCE((
                    SELECT SUM(projection_bytes)
                    FROM workspace_auxiliary_metadata_fts_projection projection
                    WHERE projection.workspace_id = workspaces.id
                ), 0),
                COALESCE((
                    SELECT SUM(LENGTH(CAST(comments.body AS BLOB)))
                    FROM comments
                    JOIN files ON files.id = comments.file_id
                    WHERE files.workspace_id = workspaces.id
                ), 0) + COALESCE((
                    SELECT SUM(LENGTH(CAST(replies.body AS BLOB)))
                    FROM comment_replies replies
                    JOIN comments ON comments.id = replies.comment_id
                    JOIN files ON files.id = comments.file_id
                    WHERE files.workspace_id = workspaces.id
                ), 0),
                COALESCE((
                    SELECT SUM(LENGTH(CAST(notifications.title AS BLOB))
                               + LENGTH(CAST(notifications.body AS BLOB)))
                    FROM notifications
                    WHERE notifications.workspace_id = workspaces.id
                ), 0),
                COALESCE((
                    SELECT SUM(LENGTH(CAST(email_outbox.subject AS BLOB))
                               + LENGTH(CAST(email_outbox.body_text AS BLOB)))
                    FROM email_outbox
                    WHERE email_outbox.workspace_id = workspaces.id
                ), 0),
                ?1
         FROM workspaces",
        params![updated_at],
    )?;
    Ok(())
}

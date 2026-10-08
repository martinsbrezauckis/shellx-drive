use rusqlite::Connection;

use super::DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES;

/// Install a database-level backstop for every source-row mutation. Rust
/// callers make an exact pre-admission decision in the same immediate
/// transaction; these triggers keep the derived ledger correct when a caller
/// is added later or a maintenance path writes a source table directly.
pub(crate) fn install_workspace_auxiliary_storage_triggers(
    conn: &Connection,
) -> rusqlite::Result<()> {
    let sql = format!(
        r#"
        DROP TRIGGER IF EXISTS workspace_auxiliary_workspace_insert;
        DROP TRIGGER IF EXISTS workspace_auxiliary_budget_growth_guard;
        DROP TRIGGER IF EXISTS workspace_auxiliary_projection_insert;
        DROP TRIGGER IF EXISTS workspace_auxiliary_projection_update_bytes;
        DROP TRIGGER IF EXISTS workspace_auxiliary_projection_move_workspace;
        DROP TRIGGER IF EXISTS workspace_auxiliary_projection_delete;
        DROP TRIGGER IF EXISTS workspace_auxiliary_files_projection_insert;
        DROP TRIGGER IF EXISTS workspace_auxiliary_files_move_workspace;
        DROP TRIGGER IF EXISTS workspace_auxiliary_files_delete_comment_replies;
        DROP TRIGGER IF EXISTS workspace_auxiliary_files_metadata_delete;
        DROP TRIGGER IF EXISTS workspace_auxiliary_file_metadata_insert;
        DROP TRIGGER IF EXISTS workspace_auxiliary_file_metadata_update;
        DROP TRIGGER IF EXISTS workspace_auxiliary_file_metadata_delete;
        DROP TRIGGER IF EXISTS workspace_auxiliary_comment_insert;
        DROP TRIGGER IF EXISTS workspace_auxiliary_comment_update_body;
        DROP TRIGGER IF EXISTS workspace_auxiliary_comment_delete;
        DROP TRIGGER IF EXISTS workspace_auxiliary_reply_insert;
        DROP TRIGGER IF EXISTS workspace_auxiliary_reply_update_body;
        DROP TRIGGER IF EXISTS workspace_auxiliary_reply_delete;
        DROP TRIGGER IF EXISTS workspace_auxiliary_notification_insert;
        DROP TRIGGER IF EXISTS workspace_auxiliary_notification_update_content;
        DROP TRIGGER IF EXISTS workspace_auxiliary_notification_move_workspace;
        DROP TRIGGER IF EXISTS workspace_auxiliary_notification_delete;
        DROP TRIGGER IF EXISTS workspace_auxiliary_email_insert;
        DROP TRIGGER IF EXISTS workspace_auxiliary_email_update_content;
        DROP TRIGGER IF EXISTS workspace_auxiliary_email_move_workspace;
        DROP TRIGGER IF EXISTS workspace_auxiliary_email_delete;

        CREATE TRIGGER workspace_auxiliary_workspace_insert
        AFTER INSERT ON workspaces BEGIN
            INSERT INTO workspace_auxiliary_usage (
                workspace_id, file_metadata_bytes, metadata_fts_projection_bytes,
                comment_reply_body_bytes, notification_bytes, email_outbox_bytes, updated_at
            ) VALUES (NEW.id, 0, 0, 0, 0, 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            ON CONFLICT(workspace_id) DO NOTHING;
        END;

        CREATE TRIGGER workspace_auxiliary_budget_growth_guard
        BEFORE UPDATE OF file_metadata_bytes, metadata_fts_projection_bytes,
                         comment_reply_body_bytes, notification_bytes, email_outbox_bytes
        ON workspace_auxiliary_usage
        WHEN (NEW.file_metadata_bytes + NEW.metadata_fts_projection_bytes
              + NEW.comment_reply_body_bytes + NEW.notification_bytes
              + NEW.email_outbox_bytes)
             > (OLD.file_metadata_bytes + OLD.metadata_fts_projection_bytes
                + OLD.comment_reply_body_bytes + OLD.notification_bytes
                + OLD.email_outbox_bytes)
         AND (NEW.file_metadata_bytes + NEW.metadata_fts_projection_bytes
              + NEW.comment_reply_body_bytes + NEW.notification_bytes
              + NEW.email_outbox_bytes) > {DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES}
        BEGIN
            SELECT RAISE(ABORT, 'workspace auxiliary storage limit exceeded');
        END;

        CREATE TRIGGER workspace_auxiliary_projection_insert
        AFTER INSERT ON workspace_auxiliary_metadata_fts_projection BEGIN
            UPDATE workspace_auxiliary_usage
            SET metadata_fts_projection_bytes = metadata_fts_projection_bytes + NEW.projection_bytes,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_projection_update_bytes
        AFTER UPDATE OF projection_bytes ON workspace_auxiliary_metadata_fts_projection
        WHEN OLD.workspace_id = NEW.workspace_id BEGIN
            UPDATE workspace_auxiliary_usage
            SET metadata_fts_projection_bytes = metadata_fts_projection_bytes
                    + NEW.projection_bytes - OLD.projection_bytes,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_projection_move_workspace
        AFTER UPDATE OF workspace_id ON workspace_auxiliary_metadata_fts_projection
        WHEN OLD.workspace_id <> NEW.workspace_id BEGIN
            UPDATE workspace_auxiliary_usage
            SET metadata_fts_projection_bytes = metadata_fts_projection_bytes - OLD.projection_bytes,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = OLD.workspace_id;
            UPDATE workspace_auxiliary_usage
            SET metadata_fts_projection_bytes = metadata_fts_projection_bytes + NEW.projection_bytes,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_projection_delete
        AFTER DELETE ON workspace_auxiliary_metadata_fts_projection BEGIN
            UPDATE workspace_auxiliary_usage
            SET metadata_fts_projection_bytes = metadata_fts_projection_bytes - OLD.projection_bytes,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = OLD.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_files_projection_insert
        AFTER INSERT ON files BEGIN
            INSERT INTO workspace_auxiliary_metadata_fts_projection (
                file_id, workspace_id, projection_bytes
            ) VALUES (
                NEW.id,
                NEW.workspace_id,
                COALESCE((
                    SELECT LENGTH(CAST(metadata.labels_json AS BLOB))
                         + LENGTH(CAST(metadata.custom_json AS BLOB))
                    FROM file_metadata metadata WHERE metadata.file_id = NEW.id
                ), 4)
            );
        END;

        CREATE TRIGGER workspace_auxiliary_files_move_workspace
        AFTER UPDATE OF workspace_id ON files
        WHEN OLD.workspace_id <> NEW.workspace_id BEGIN
            UPDATE workspace_auxiliary_usage
            SET file_metadata_bytes = file_metadata_bytes - COALESCE((
                SELECT LENGTH(CAST(metadata.labels_json AS BLOB))
                     + LENGTH(CAST(metadata.custom_json AS BLOB))
                FROM file_metadata metadata WHERE metadata.file_id = OLD.id
            ), 0), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = OLD.workspace_id;
            UPDATE workspace_auxiliary_usage
            SET file_metadata_bytes = file_metadata_bytes + COALESCE((
                SELECT LENGTH(CAST(metadata.labels_json AS BLOB))
                     + LENGTH(CAST(metadata.custom_json AS BLOB))
                FROM file_metadata metadata WHERE metadata.file_id = NEW.id
            ), 0), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
            UPDATE workspace_auxiliary_metadata_fts_projection
            SET workspace_id = NEW.workspace_id WHERE file_id = NEW.id;
        END;

        -- Account descendant collaboration rows before a file's FK cascades.
        -- The child triggers below observe a removed parent during that cascade
        -- and deliberately no-op, so every body is subtracted exactly once.
        CREATE TRIGGER workspace_auxiliary_files_delete_comment_replies
        BEFORE DELETE ON files BEGIN
            UPDATE workspace_auxiliary_usage
            SET comment_reply_body_bytes = comment_reply_body_bytes
                    - COALESCE((
                        SELECT SUM(LENGTH(CAST(comments.body AS BLOB)))
                        FROM comments WHERE comments.file_id = OLD.id
                    ), 0)
                    - COALESCE((
                        SELECT SUM(LENGTH(CAST(replies.body AS BLOB)))
                        FROM comment_replies replies
                        JOIN comments ON comments.id = replies.comment_id
                        WHERE comments.file_id = OLD.id
                    ), 0),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = OLD.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_files_metadata_delete
        BEFORE DELETE ON files BEGIN
            UPDATE workspace_auxiliary_usage
            SET file_metadata_bytes = file_metadata_bytes - COALESCE((
                SELECT LENGTH(CAST(metadata.labels_json AS BLOB))
                     + LENGTH(CAST(metadata.custom_json AS BLOB))
                FROM file_metadata metadata WHERE metadata.file_id = OLD.id
            ), 0), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = OLD.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_file_metadata_insert
        AFTER INSERT ON file_metadata BEGIN
            UPDATE workspace_auxiliary_usage
            SET file_metadata_bytes = file_metadata_bytes
                    + LENGTH(CAST(NEW.labels_json AS BLOB))
                    + LENGTH(CAST(NEW.custom_json AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = (SELECT workspace_id FROM files WHERE id = NEW.file_id);
            UPDATE workspace_auxiliary_metadata_fts_projection
            SET projection_bytes = LENGTH(CAST(NEW.labels_json AS BLOB))
                    + LENGTH(CAST(NEW.custom_json AS BLOB))
            WHERE file_id = NEW.file_id;
        END;

        CREATE TRIGGER workspace_auxiliary_file_metadata_update
        AFTER UPDATE OF labels_json, custom_json ON file_metadata BEGIN
            UPDATE workspace_auxiliary_usage
            SET file_metadata_bytes = file_metadata_bytes
                    + LENGTH(CAST(NEW.labels_json AS BLOB))
                    + LENGTH(CAST(NEW.custom_json AS BLOB))
                    - LENGTH(CAST(OLD.labels_json AS BLOB))
                    - LENGTH(CAST(OLD.custom_json AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = (SELECT workspace_id FROM files WHERE id = NEW.file_id);
            UPDATE workspace_auxiliary_metadata_fts_projection
            SET projection_bytes = LENGTH(CAST(NEW.labels_json AS BLOB))
                    + LENGTH(CAST(NEW.custom_json AS BLOB))
            WHERE file_id = NEW.file_id;
        END;

        CREATE TRIGGER workspace_auxiliary_file_metadata_delete
        BEFORE DELETE ON file_metadata
        WHEN EXISTS (SELECT 1 FROM files WHERE id = OLD.file_id) BEGIN
            UPDATE workspace_auxiliary_usage
            SET file_metadata_bytes = file_metadata_bytes
                    - LENGTH(CAST(OLD.labels_json AS BLOB))
                    - LENGTH(CAST(OLD.custom_json AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = (SELECT workspace_id FROM files WHERE id = OLD.file_id);
            UPDATE workspace_auxiliary_metadata_fts_projection
            SET projection_bytes = 4 WHERE file_id = OLD.file_id;
        END;

        CREATE TRIGGER workspace_auxiliary_comment_insert
        AFTER INSERT ON comments BEGIN
            UPDATE workspace_auxiliary_usage
            SET comment_reply_body_bytes = comment_reply_body_bytes + LENGTH(CAST(NEW.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = (
                SELECT workspace_id FROM files WHERE id = NEW.file_id
            );
        END;

        CREATE TRIGGER workspace_auxiliary_comment_update_body
        AFTER UPDATE OF body ON comments BEGIN
            UPDATE workspace_auxiliary_usage
            SET comment_reply_body_bytes = comment_reply_body_bytes
                    + LENGTH(CAST(NEW.body AS BLOB)) - LENGTH(CAST(OLD.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = (
                SELECT workspace_id FROM files WHERE id = NEW.file_id
            );
        END;

        -- Direct comment deletion must subtract both its own body and all of
        -- its replies. During a file cascade the parent file is already gone,
        -- so the file trigger above is the sole accounting authority.
        CREATE TRIGGER workspace_auxiliary_comment_delete
        BEFORE DELETE ON comments BEGIN
            UPDATE workspace_auxiliary_usage
            SET comment_reply_body_bytes = comment_reply_body_bytes
                    - LENGTH(CAST(OLD.body AS BLOB))
                    - COALESCE((
                        SELECT SUM(LENGTH(CAST(replies.body AS BLOB)))
                        FROM comment_replies replies
                        WHERE replies.comment_id = OLD.id
                    ), 0),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = (SELECT workspace_id FROM files WHERE id = OLD.file_id);
        END;

        CREATE TRIGGER workspace_auxiliary_reply_insert
        AFTER INSERT ON comment_replies BEGIN
            UPDATE workspace_auxiliary_usage
            SET comment_reply_body_bytes = comment_reply_body_bytes + LENGTH(CAST(NEW.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = (
                SELECT files.workspace_id FROM comments
                JOIN files ON files.id = comments.file_id
                WHERE comments.id = NEW.comment_id
            );
        END;

        CREATE TRIGGER workspace_auxiliary_reply_update_body
        AFTER UPDATE OF body ON comment_replies BEGIN
            UPDATE workspace_auxiliary_usage
            SET comment_reply_body_bytes = comment_reply_body_bytes
                    + LENGTH(CAST(NEW.body AS BLOB)) - LENGTH(CAST(OLD.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = (
                SELECT files.workspace_id FROM comments
                JOIN files ON files.id = comments.file_id
                WHERE comments.id = NEW.comment_id
            );
        END;

        CREATE TRIGGER workspace_auxiliary_reply_delete
        BEFORE DELETE ON comment_replies BEGIN
            UPDATE workspace_auxiliary_usage
            SET comment_reply_body_bytes = comment_reply_body_bytes - LENGTH(CAST(OLD.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = (
                SELECT files.workspace_id FROM comments
                JOIN files ON files.id = comments.file_id
                WHERE comments.id = OLD.comment_id
            );
        END;

        CREATE TRIGGER workspace_auxiliary_notification_insert
        AFTER INSERT ON notifications
        WHEN NEW.workspace_id IS NOT NULL BEGIN
            UPDATE workspace_auxiliary_usage
            SET notification_bytes = notification_bytes
                    + LENGTH(CAST(NEW.title AS BLOB)) + LENGTH(CAST(NEW.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_notification_update_content
        AFTER UPDATE OF title, body ON notifications
        WHEN OLD.workspace_id = NEW.workspace_id AND NEW.workspace_id IS NOT NULL BEGIN
            UPDATE workspace_auxiliary_usage
            SET notification_bytes = notification_bytes
                    + LENGTH(CAST(NEW.title AS BLOB)) + LENGTH(CAST(NEW.body AS BLOB))
                    - LENGTH(CAST(OLD.title AS BLOB)) - LENGTH(CAST(OLD.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_notification_move_workspace
        AFTER UPDATE OF workspace_id ON notifications
        WHEN OLD.workspace_id IS NOT NEW.workspace_id BEGIN
            UPDATE workspace_auxiliary_usage
            SET notification_bytes = notification_bytes
                    - LENGTH(CAST(OLD.title AS BLOB)) - LENGTH(CAST(OLD.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = OLD.workspace_id;
            UPDATE workspace_auxiliary_usage
            SET notification_bytes = notification_bytes
                    + LENGTH(CAST(NEW.title AS BLOB)) + LENGTH(CAST(NEW.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_notification_delete
        AFTER DELETE ON notifications
        WHEN OLD.workspace_id IS NOT NULL BEGIN
            UPDATE workspace_auxiliary_usage
            SET notification_bytes = notification_bytes
                    - LENGTH(CAST(OLD.title AS BLOB)) - LENGTH(CAST(OLD.body AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = OLD.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_email_insert
        AFTER INSERT ON email_outbox
        WHEN NEW.workspace_id IS NOT NULL BEGIN
            UPDATE workspace_auxiliary_usage
            SET email_outbox_bytes = email_outbox_bytes
                    + LENGTH(CAST(NEW.subject AS BLOB)) + LENGTH(CAST(NEW.body_text AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_email_update_content
        AFTER UPDATE OF subject, body_text ON email_outbox
        WHEN OLD.workspace_id = NEW.workspace_id AND NEW.workspace_id IS NOT NULL BEGIN
            UPDATE workspace_auxiliary_usage
            SET email_outbox_bytes = email_outbox_bytes
                    + LENGTH(CAST(NEW.subject AS BLOB)) + LENGTH(CAST(NEW.body_text AS BLOB))
                    - LENGTH(CAST(OLD.subject AS BLOB)) - LENGTH(CAST(OLD.body_text AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_email_move_workspace
        AFTER UPDATE OF workspace_id ON email_outbox
        WHEN OLD.workspace_id IS NOT NEW.workspace_id BEGIN
            UPDATE workspace_auxiliary_usage
            SET email_outbox_bytes = email_outbox_bytes
                    - LENGTH(CAST(OLD.subject AS BLOB)) - LENGTH(CAST(OLD.body_text AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = OLD.workspace_id;
            UPDATE workspace_auxiliary_usage
            SET email_outbox_bytes = email_outbox_bytes
                    + LENGTH(CAST(NEW.subject AS BLOB)) + LENGTH(CAST(NEW.body_text AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = NEW.workspace_id;
        END;

        CREATE TRIGGER workspace_auxiliary_email_delete
        AFTER DELETE ON email_outbox
        WHEN OLD.workspace_id IS NOT NULL BEGIN
            UPDATE workspace_auxiliary_usage
            SET email_outbox_bytes = email_outbox_bytes
                    - LENGTH(CAST(OLD.subject AS BLOB)) - LENGTH(CAST(OLD.body_text AS BLOB)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE workspace_id = OLD.workspace_id;
        END;
        "#
    );
    conn.execute_batch(&sql)
}

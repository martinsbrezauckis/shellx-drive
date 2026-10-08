mod compatibility;
mod core;
mod receipt_retention;
#[cfg(test)]
mod tests;

use super::folder_templates::{
    MAX_FOLDER_TEMPLATES_PER_WORKSPACE, MAX_FOLDER_TEMPLATE_CONTENT_BYTES,
    MAX_FOLDER_TEMPLATE_ITEMS, MAX_WORKSPACE_FOLDER_TEMPLATE_CONTENT_BYTES,
};
use super::{
    auxiliary_storage::{
        install_workspace_auxiliary_storage_triggers,
        rebuild_workspace_auxiliary_storage_usage_in_tx,
    },
    ensure_column, imports,
    uploads::TERMINAL_UPLOAD_RETENTION_PER_WORKSPACE,
    Storage, MAX_FILE_REVISIONS, MAX_PINNED_FILE_REVISIONS,
};
use crate::auth::ADMIN_ACTOR;

impl Storage {
    pub fn migrate(&self) -> rusqlite::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        core::migrate(&conn)?;
        receipt_retention::install(&conn)?;
        super::delta_stats::reconcile(&mut conn)?;
        imports::migrate(&conn)?;
        ensure_column(
            &conn,
            "files",
            "content_bytes",
            "content_bytes INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &conn,
            "files",
            "drop_inbox_owner_id",
            "drop_inbox_owner_id TEXT",
        )?;
        ensure_column(&conn, "drops", "inbox_file_id", "inbox_file_id TEXT")?;
        ensure_column(
            &conn,
            "auth_attempts",
            "client_fingerprint",
            "client_fingerprint TEXT",
        )?;
        ensure_column(
            &conn,
            "security_events",
            "low_authority",
            "low_authority INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &conn,
            "file_revisions",
            "content_bytes",
            "content_bytes INTEGER NOT NULL DEFAULT 0",
        )?;
        // Extracted text is derived from a precise immutable file subject. An
        // old database cannot prove which revision or blob produced its rows,
        // so mark those legacy rows invalid first and remove them below rather
        // than treating their text as current after the schema upgrade.
        ensure_column(
            &conn,
            "file_text_index",
            "source_revision",
            "source_revision INTEGER NOT NULL DEFAULT -1",
        )?;
        ensure_column(
            &conn,
            "file_text_index",
            "source_content_hash",
            "source_content_hash TEXT",
        )?;
        conn.execute(
            "DELETE FROM file_text_index
             WHERE source_revision < 0 OR source_content_hash IS NULL",
            [],
        )?;
        // FTS is only a projection. Rewrite its content column from an index
        // row that still matches the current file subject; this both makes a
        // partially interrupted legacy upgrade retry-safe and prevents legacy
        // snippets from surviving after their source rows were discarded.
        conn.execute(
            "UPDATE file_search_fts
             SET content = COALESCE((
                 SELECT file_text_index.content_text
                 FROM file_text_index
                 JOIN files ON files.id = file_text_index.file_id
                 WHERE file_text_index.file_id = file_search_fts.file_id
                   AND file_text_index.workspace_id = files.workspace_id
                   AND file_text_index.source_revision = files.revision
                   AND file_text_index.source_content_hash IS files.content_hash
             ), '')",
            [],
        )?;
        ensure_column(&conn, "files", "trashed_at", "trashed_at TEXT")?;
        // Custom folder cover image (references an image blob by SHA-256).
        ensure_column(&conn, "files", "cover_hash", "cover_hash TEXT")?;
        ensure_column(
            &conn,
            "files",
            "cover_bytes",
            "cover_bytes INTEGER NOT NULL DEFAULT 0",
        )?;
        conn.execute(
            "UPDATE files
             SET cover_bytes = 0
             WHERE cover_bytes < 0 OR cover_hash IS NULL",
            [],
        )?;
        // Older builds could write ordinary file bodies onto folder rows.
        // Restore already rejects that state, so repair it before installing
        // the durable invariant and discard the inaccessible folder revisions.
        conn.execute(
            "DELETE FROM file_revisions
             WHERE file_id IN (
                 SELECT id FROM files
                 WHERE kind = 'folder'
                   AND (content_hash IS NOT NULL OR content_bytes <> 0)
             )",
            [],
        )?;
        conn.execute(
            "UPDATE files
             SET content_hash = NULL, content_bytes = 0
             WHERE kind = 'folder'
               AND (content_hash IS NOT NULL OR content_bytes <> 0)",
            [],
        )?;
        conn.execute(
            "UPDATE files
             SET cover_hash = NULL, cover_bytes = 0
             WHERE kind = 'file'
               AND (cover_hash IS NOT NULL OR cover_bytes <> 0)",
            [],
        )?;
        conn.execute_batch(
            "DROP TRIGGER IF EXISTS files_cover_bytes_insert_guard;
             DROP TRIGGER IF EXISTS files_cover_bytes_update_guard;
             DROP TRIGGER IF EXISTS files_kind_content_insert_guard;
             DROP TRIGGER IF EXISTS files_kind_content_update_guard;
             CREATE TRIGGER files_cover_bytes_insert_guard
             BEFORE INSERT ON files
             WHEN NEW.cover_bytes < 0 OR (NEW.cover_hash IS NULL AND NEW.cover_bytes <> 0)
             BEGIN
                 SELECT RAISE(ABORT, 'invalid file cover byte accounting');
             END;
             CREATE TRIGGER files_cover_bytes_update_guard
             BEFORE UPDATE OF cover_hash, cover_bytes ON files
             WHEN NEW.cover_bytes < 0 OR (NEW.cover_hash IS NULL AND NEW.cover_bytes <> 0)
             BEGIN
                 SELECT RAISE(ABORT, 'invalid file cover byte accounting');
             END;
             CREATE TRIGGER files_kind_content_insert_guard
             BEFORE INSERT ON files
             WHEN NEW.kind NOT IN ('file', 'folder')
               OR (NEW.kind = 'folder' AND (NEW.content_hash IS NOT NULL OR NEW.content_bytes <> 0))
               OR (NEW.kind = 'file' AND (NEW.cover_hash IS NOT NULL OR NEW.cover_bytes <> 0))
             BEGIN
                 SELECT RAISE(ABORT, 'invalid file kind content invariant');
             END;
             CREATE TRIGGER files_kind_content_update_guard
             BEFORE UPDATE OF kind, content_hash, content_bytes, cover_hash, cover_bytes ON files
             WHEN NEW.kind NOT IN ('file', 'folder')
               OR (NEW.kind = 'folder' AND (NEW.content_hash IS NOT NULL OR NEW.content_bytes <> 0))
               OR (NEW.kind = 'file' AND (NEW.cover_hash IS NOT NULL OR NEW.cover_bytes <> 0))
             BEGIN
                 SELECT RAISE(ABORT, 'invalid file kind content invariant');
             END;",
        )?;
        ensure_column(
            &conn,
            "file_revisions",
            "pinned",
            "pinned INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &conn,
            "file_revisions",
            "conflict_of_file_id",
            "conflict_of_file_id TEXT",
        )?;
        ensure_column(
            &conn,
            "file_previews",
            "thumbnail_hash",
            "thumbnail_hash TEXT",
        )?;
        ensure_column(
            &conn,
            "file_previews",
            "thumbnail_content_type",
            "thumbnail_content_type TEXT",
        )?;
        ensure_column(
            &conn,
            "file_previews",
            "thumbnail_bytes",
            "thumbnail_bytes INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(&conn, "file_previews", "width", "width INTEGER")?;
        ensure_column(&conn, "file_previews", "height", "height INTEGER")?;
        ensure_column(
            &conn,
            "file_previews",
            "status",
            "status TEXT NOT NULL DEFAULT 'ready'",
        )?;
        // Preview reads join against the current file revision. Keep an older
        // row long enough for the next preview job or file lifecycle cleanup
        // to reclaim its thumbnail blob rather than orphaning it in a trigger.
        conn.execute_batch("DROP TRIGGER IF EXISTS file_previews_current_revision_update;")?;
        ensure_column(
            &conn,
            "share_access_grants",
            "authorization_fingerprint",
            "authorization_fingerprint TEXT",
        )?;
        ensure_column(
            &conn,
            "backup_jobs",
            "source_credential_kind",
            "source_credential_kind TEXT",
        )?;
        ensure_column(
            &conn,
            "backup_jobs",
            "source_credential_id",
            "source_credential_id TEXT",
        )?;
        ensure_column(
            &conn,
            "backup_jobs",
            "source_credential_generation",
            "source_credential_generation TEXT",
        )?;
        ensure_column(
            &conn,
            "auth_accounts",
            "security_version",
            "security_version INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &conn,
            "auth_accounts",
            "totp_last_used_counter",
            "totp_last_used_counter INTEGER",
        )?;
        // Historic agent rows recorded only a creator email. The reserved
        // operator marker cannot distinguish an actual server-created grant
        // from a human collision, so preserve that ambiguity explicitly and
        // make the authorization predicate deny it until the grant is reissued.
        ensure_column(
            &conn,
            "agent_principals",
            "creator_authority_kind",
            "creator_authority_kind TEXT NOT NULL DEFAULT 'user' \
             CHECK (creator_authority_kind IN ('user', 'operator', 'legacy_ambiguous'))",
        )?;
        ensure_column(
            &conn,
            "agent_folder_grants",
            "creator_authority_kind",
            "creator_authority_kind TEXT NOT NULL DEFAULT 'user' \
             CHECK (creator_authority_kind IN ('user', 'operator', 'legacy_ambiguous'))",
        )?;
        conn.execute(
            "UPDATE agent_principals
             SET creator_authority_kind = 'legacy_ambiguous'
             WHERE creator_authority_kind = 'user'
               AND lower(trim(created_by)) = ?1",
            [ADMIN_ACTOR],
        )?;
        conn.execute(
            "UPDATE agent_folder_grants
             SET creator_authority_kind = 'legacy_ambiguous'
             WHERE creator_authority_kind = 'user'
               AND lower(trim(created_by)) = ?1",
            [ADMIN_ACTOR],
        )?;
        // Proof fingerprints bind public Drop session ownership, while durable
        // resource admission must use a server-derived transport partition.
        // Legacy rows cannot prove their originating transport, so place all
        // of them in one conservative partition instead of copying the
        // caller-selected proof identity into the abuse-control boundary.
        ensure_column(
            &conn,
            "drop_upload_sessions",
            "transport_fingerprint",
            "transport_fingerprint TEXT NOT NULL DEFAULT 'legacy-transport-v1'",
        )?;
        conn.execute(
            "UPDATE drop_upload_sessions
             SET transport_fingerprint = 'legacy-transport-v1'
             WHERE trim(transport_fingerprint) = ''",
            [],
        )?;
        ensure_column(&conn, "auth_sessions", "client_ip", "client_ip TEXT")?;
        ensure_column(&conn, "auth_sessions", "user_agent", "user_agent TEXT")?;
        ensure_column(&conn, "auth_sessions", "last_seen_at", "last_seen_at TEXT")?;
        ensure_column(
            &conn,
            "drops",
            "uploaded_bytes",
            "uploaded_bytes INTEGER NOT NULL DEFAULT 0",
        )?;
        conn.execute(
            "UPDATE drops
             SET uploaded_bytes = COALESCE((
                 SELECT SUM(CASE WHEN sessions.total_size > 0 THEN sessions.total_size ELSE 1 END)
                 FROM drop_upload_sessions sessions
                 WHERE sessions.drop_id = drops.id
                   AND sessions.status = 'completed'
                   AND sessions.file_id IS NOT NULL
             ), 0)",
            [],
        )?;
        conn.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS drop_upload_file_removed_usage
             AFTER UPDATE OF file_id ON drop_upload_sessions
             WHEN OLD.status = 'completed' AND OLD.file_id IS NOT NULL AND NEW.file_id IS NULL
             BEGIN
                 UPDATE drops
                 SET uploaded_bytes = MAX(
                     0,
                     uploaded_bytes - CASE WHEN OLD.total_size > 0 THEN OLD.total_size ELSE 1 END
                 )
                 WHERE id = OLD.drop_id;
             END;",
        )?;
        ensure_column(
            &conn,
            "office_edit_sessions",
            "source_credential_kind",
            "source_credential_kind TEXT NOT NULL DEFAULT 'legacy'",
        )?;
        ensure_column(
            &conn,
            "office_edit_sessions",
            "source_credential_id",
            "source_credential_id TEXT",
        )?;
        ensure_column(
            &conn,
            "office_edit_sessions",
            "source_credential_generation",
            "source_credential_generation TEXT",
        )?;
        conn.execute(
            "UPDATE office_edit_sessions
             SET used_at = COALESCE(used_at, created_at)
             WHERE source_credential_kind IN ('operator', 'user_session')
               AND source_credential_generation IS NULL",
            [],
        )?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_files_content_hash_referenced
                ON files(content_hash) WHERE content_hash IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_files_cover_hash_referenced
                ON files(cover_hash) WHERE cover_hash IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_files_live_updated
                ON files(trashed, updated_at DESC, id DESC);
             CREATE INDEX IF NOT EXISTS idx_workspace_members_actor_access
                ON workspace_members(user_id, workspace_id, role, expires_at);
             CREATE INDEX IF NOT EXISTS idx_group_members_actor_access
                ON group_members(user_id, group_id);
             CREATE INDEX IF NOT EXISTS idx_workspace_group_grants_access
                ON workspace_group_grants(group_id, workspace_id, role);
             CREATE INDEX IF NOT EXISTS idx_file_revisions_content_hash_referenced
                ON file_revisions(content_hash) WHERE content_hash IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_file_previews_thumbnail_hash_referenced
                ON file_previews(thumbnail_hash) WHERE thumbnail_hash IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_upload_sessions_workspace_terminal_updated
                ON upload_sessions(workspace_id, completed, canceled, updated_at DESC, id DESC);
             CREATE INDEX IF NOT EXISTS idx_drop_upload_sessions_transport_status
                ON drop_upload_sessions(transport_fingerprint, status);
             CREATE INDEX IF NOT EXISTS idx_activity_retention
                ON activity(created_at DESC, id DESC);
             CREATE INDEX IF NOT EXISTS idx_mobile_offline_actor_marked
                ON mobile_offline_files(actor_email, marked_at DESC, file_id DESC);
             CREATE INDEX IF NOT EXISTS idx_mobile_offline_actor_workspace
                ON mobile_offline_files(actor_email, workspace_id, file_id);
             CREATE INDEX IF NOT EXISTS idx_office_sessions_source_active
                ON office_edit_sessions(source_credential_kind, source_credential_id, used_at);
             CREATE INDEX IF NOT EXISTS idx_auth_sessions_active_actor_created
                ON auth_sessions(actor_email, created_at DESC, id DESC)
                WHERE revoked_at IS NULL;
             CREATE INDEX IF NOT EXISTS idx_auth_sessions_active_created
                ON auth_sessions(created_at DESC, id DESC)
                WHERE revoked_at IS NULL;
             CREATE TRIGGER IF NOT EXISTS activity_bounded_retention
             AFTER INSERT ON activity
             WHEN (SELECT COUNT(*) FROM activity) > 100000
             BEGIN
               DELETE FROM activity
               WHERE id IN (
                 SELECT id FROM activity
                 ORDER BY created_at ASC, id ASC
                 LIMIT 10000
               );
             END;",
        )?;
        // A file-text row is valid only for the exact current file revision and
        // content blob. Keep this invariant in SQLite as well as in the Rust
        // API, because FTS publication must never make an old worker's output
        // searchable after a newer file mutation commits.
        conn.execute_batch(
            "DROP TRIGGER IF EXISTS file_text_index_subject_insert_guard;
             DROP TRIGGER IF EXISTS file_text_index_subject_update_guard;
             DROP TRIGGER IF EXISTS files_search_content_subject_invalidate;
             CREATE TRIGGER file_text_index_subject_insert_guard
             BEFORE INSERT ON file_text_index
             WHEN NOT EXISTS (
                 SELECT 1 FROM files
                 WHERE id = NEW.file_id
                   AND workspace_id = NEW.workspace_id
                   AND kind = 'file'
                   AND trashed = 0
                   AND revision = NEW.source_revision
                   AND content_hash IS NEW.source_content_hash
             )
             BEGIN
                 SELECT RAISE(ABORT, 'file text index source does not match current file');
             END;
             CREATE TRIGGER file_text_index_subject_update_guard
             BEFORE UPDATE OF file_id, workspace_id, source_revision, source_content_hash
             ON file_text_index
             WHEN NOT EXISTS (
                 SELECT 1 FROM files
                 WHERE id = NEW.file_id
                   AND workspace_id = NEW.workspace_id
                   AND kind = 'file'
                   AND trashed = 0
                   AND revision = NEW.source_revision
                   AND content_hash IS NEW.source_content_hash
             )
             BEGIN
                 SELECT RAISE(ABORT, 'file text index source does not match current file');
             END;
             CREATE TRIGGER files_search_content_subject_invalidate
             AFTER UPDATE OF revision, content_hash ON files
             WHEN OLD.revision IS NOT NEW.revision
                OR OLD.content_hash IS NOT NEW.content_hash
             BEGIN
                 DELETE FROM file_text_index WHERE file_id = NEW.id;
                 UPDATE file_search_fts SET content = '' WHERE file_id = NEW.id;
             END;",
        )?;
        conn.execute_batch(&format!(
            "DROP TRIGGER IF EXISTS file_revisions_bounded_insert;
             DROP TRIGGER IF EXISTS file_revisions_bounded_pin;
             CREATE TRIGGER file_revisions_bounded_insert
             BEFORE INSERT ON file_revisions
             WHEN (SELECT COUNT(*) FROM file_revisions WHERE file_id = NEW.file_id) >= {MAX_FILE_REVISIONS}
             BEGIN
               SELECT RAISE(ABORT, 'file revision limit exceeded');
             END;
             CREATE TRIGGER file_revisions_bounded_pin
             BEFORE UPDATE OF pinned ON file_revisions
             WHEN NEW.pinned = 1
               AND OLD.pinned = 0
               AND (SELECT COUNT(*) FROM file_revisions WHERE file_id = NEW.file_id AND pinned = 1) >= {MAX_PINNED_FILE_REVISIONS}
             BEGIN
               SELECT RAISE(ABORT, 'pinned file revision limit exceeded');
             END;"
        ))?;
        conn.execute_batch(&format!(
            "DROP TRIGGER IF EXISTS folder_templates_bounded_insert;
             DROP TRIGGER IF EXISTS folder_template_items_bounded_insert;
             CREATE TRIGGER folder_templates_bounded_insert
             BEFORE INSERT ON folder_templates
             WHEN (SELECT COUNT(*) FROM folder_templates WHERE workspace_id = NEW.workspace_id) >= {MAX_FOLDER_TEMPLATES_PER_WORKSPACE}
             BEGIN
               SELECT RAISE(ABORT, 'folder template limit exceeded');
             END;
             CREATE TRIGGER folder_template_items_bounded_insert
             BEFORE INSERT ON folder_template_items
             BEGIN
               SELECT CASE
                 WHEN (SELECT COUNT(*) FROM folder_template_items WHERE template_id = NEW.template_id) >= {MAX_FOLDER_TEMPLATE_ITEMS}
                 THEN RAISE(ABORT, 'folder template item limit exceeded')
               END;
               SELECT CASE
                 WHEN COALESCE((
                   SELECT SUM(LENGTH(CAST(content AS BLOB)))
                   FROM folder_template_items WHERE template_id = NEW.template_id
                 ), 0) + COALESCE(LENGTH(CAST(NEW.content AS BLOB)), 0) > {MAX_FOLDER_TEMPLATE_CONTENT_BYTES}
                 THEN RAISE(ABORT, 'folder template content limit exceeded')
               END;
               SELECT CASE
                 WHEN COALESCE((
                   SELECT SUM(LENGTH(CAST(fti.content AS BLOB)))
                   FROM folder_template_items fti
                   JOIN folder_templates ft ON ft.id = fti.template_id
                   WHERE ft.workspace_id = (
                     SELECT workspace_id FROM folder_templates WHERE id = NEW.template_id
                   )
                 ), 0) + COALESCE(LENGTH(CAST(NEW.content AS BLOB)), 0) > {MAX_WORKSPACE_FOLDER_TEMPLATE_CONTENT_BYTES}
                 THEN RAISE(ABORT, 'workspace folder template content limit exceeded')
               END;
             END;"
        ))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS account_private_workspaces (
                user_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES auth_accounts(user_id) ON DELETE CASCADE,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS human_item_grants (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                root_file_id TEXT NOT NULL,
                principal_kind TEXT NOT NULL
                    CHECK (principal_kind IN ('account', 'group', 'everyone')),
                principal_ref TEXT,
                role TEXT NOT NULL CHECK (role IN ('viewer', 'editor')),
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT,
                publication_pending INTEGER NOT NULL DEFAULT 0
                    CHECK (publication_pending IN (0, 1)),
                CHECK (
                    (principal_kind = 'everyone' AND principal_ref IS NULL)
                    OR (principal_kind IN ('account', 'group')
                        AND principal_ref IS NOT NULL AND trim(principal_ref) <> '')
                ),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (root_file_id) REFERENCES files(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_human_item_grants_root_current
                ON human_item_grants(root_file_id, revoked_at, expires_at, id);
            CREATE INDEX IF NOT EXISTS idx_human_item_grants_workspace_current
                ON human_item_grants(workspace_id, revoked_at, expires_at, id);
            CREATE INDEX IF NOT EXISTS idx_human_item_grants_everyone_page
                ON human_item_grants(root_file_id, id)
                WHERE principal_kind = 'everyone' AND revoked_at IS NULL
                  AND publication_pending = 0;
            CREATE INDEX IF NOT EXISTS idx_human_item_grants_scoped_everyone_page
                ON human_item_grants(workspace_id, root_file_id, id)
                WHERE principal_kind = 'everyone' AND revoked_at IS NULL
                  AND publication_pending = 0;
            CREATE INDEX IF NOT EXISTS idx_human_item_grants_account_current
                ON human_item_grants(principal_ref, root_file_id, expires_at, id)
                WHERE principal_kind = 'account' AND revoked_at IS NULL;
            CREATE INDEX IF NOT EXISTS idx_human_item_grants_group_current
                ON human_item_grants(principal_ref, root_file_id, expires_at, id)
                WHERE principal_kind = 'group' AND revoked_at IS NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_human_item_grants_one_current_principal
                ON human_item_grants(root_file_id, principal_kind, COALESCE(principal_ref, ''))
                WHERE revoked_at IS NULL AND publication_pending = 0;
            CREATE TRIGGER IF NOT EXISTS human_item_grants_workspace_root_insert
            BEFORE INSERT ON human_item_grants
            WHEN NOT EXISTS (
                SELECT 1 FROM files
                WHERE id = NEW.root_file_id AND workspace_id = NEW.workspace_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'human item grant root/workspace mismatch');
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_grants_workspace_root_update
            BEFORE UPDATE OF workspace_id, root_file_id ON human_item_grants
            WHEN NOT EXISTS (
                SELECT 1 FROM files
                WHERE id = NEW.root_file_id AND workspace_id = NEW.workspace_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'human item grant root/workspace mismatch');
            END;
            CREATE TABLE IF NOT EXISTS human_item_access_generation (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                generation INTEGER NOT NULL CHECK (generation >= 0)
            );
            INSERT OR IGNORE INTO human_item_access_generation (id, generation) VALUES (1, 1);
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_grant_insert
            AFTER INSERT ON human_item_grants BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_grant_update
            AFTER UPDATE ON human_item_grants BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_grant_delete
            AFTER DELETE ON human_item_grants BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_group_member_insert
            AFTER INSERT ON group_members BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_group_member_delete
            AFTER DELETE ON group_members BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_workspace_member_insert
            AFTER INSERT ON workspace_members BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_workspace_member_update
            AFTER UPDATE ON workspace_members BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_workspace_member_delete
            AFTER DELETE ON workspace_members BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_workspace_group_insert
            AFTER INSERT ON workspace_group_grants BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_workspace_group_update
            AFTER UPDATE ON workspace_group_grants BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_workspace_group_delete
            AFTER DELETE ON workspace_group_grants BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_account_disable
            AFTER UPDATE OF disabled_at ON auth_accounts BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_file_authority
            AFTER UPDATE OF parent_id, trashed, workspace_id ON files BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            CREATE TRIGGER IF NOT EXISTS human_item_access_generation_workspace_authority
            AFTER UPDATE OF archived_at ON workspaces BEGIN
                UPDATE human_item_access_generation SET generation = generation + 1 WHERE id = 1;
            END;
            INSERT OR IGNORE INTO server_settings (key, value, updated_at)
            VALUES ('human_item_grants.everyone_enabled', 'false', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));",
        )?;
        // Older accounts did not have an explicit My files root.  A workspace
        // with historical co-owners is owned canonically by its earliest
        // eligible account (created_at, user_id), so its UNIQUE private map is
        // never won by SQLite's incidental row order.  Other co-owners retain
        // ordinary whole-workspace membership and receive private-v1 only when
        // they own no distinct canonical workspace.  Within each account,
        // active workspaces win before creation/id order.  This preserves an
        // existing canonical view/data instead of creating an empty twin.
        conn.execute_batch(
            "INSERT OR IGNORE INTO account_private_workspaces (user_id, workspace_id, created_at)
             WITH direct_owners AS (
               SELECT accounts.user_id, accounts.created_at AS account_created_at,
                      workspaces.id AS workspace_id, workspaces.created_at AS workspace_created_at,
                      workspaces.archived_at,
                      ROW_NUMBER() OVER (
                        PARTITION BY workspaces.id
                        ORDER BY accounts.created_at ASC, accounts.user_id ASC
                      ) AS workspace_owner_rank
               FROM auth_accounts accounts
               JOIN workspace_members members ON members.user_id = accounts.user_id
               JOIN workspaces ON workspaces.id = members.workspace_id
               WHERE members.role = 'owner'
             ), ranked_owned AS (
               SELECT user_id, workspace_id, account_created_at,
                      ROW_NUMBER() OVER (
                        PARTITION BY user_id
                        ORDER BY (archived_at IS NULL) DESC,
                                 workspace_created_at ASC, workspace_id ASC
                      ) AS owner_rank
               FROM direct_owners WHERE workspace_owner_rank = 1
             )
             SELECT user_id, workspace_id, account_created_at
             FROM ranked_owned WHERE owner_rank = 1;
             INSERT OR IGNORE INTO workspaces
                (id, tenant_id, name, storage_mode, created_at, updated_at)
             SELECT 'private-v1:' || accounts.user_id, NULL, 'My files', 'open',
                    accounts.created_at, accounts.updated_at
             FROM auth_accounts accounts
             WHERE NOT EXISTS (
                 SELECT 1 FROM account_private_workspaces private
                 WHERE private.user_id = accounts.user_id
             );
             INSERT OR IGNORE INTO workspace_members (workspace_id, user_id, role)
             SELECT 'private-v1:' || accounts.user_id, accounts.user_id, 'owner'
             FROM auth_accounts accounts
             WHERE NOT EXISTS (
                 SELECT 1 FROM account_private_workspaces private
                 WHERE private.user_id = accounts.user_id
             );
             INSERT OR IGNORE INTO account_private_workspaces (user_id, workspace_id, created_at)
             SELECT accounts.user_id, 'private-v1:' || accounts.user_id, accounts.created_at
             FROM auth_accounts accounts;",
        )?;
        compatibility::migrate(&conn)?;
        super::desktop_agent::install_schema(&conn)?;
        install_workspace_auxiliary_storage_triggers(&conn)?;
        rebuild_workspace_auxiliary_storage_usage_in_tx(&conn)?;
        conn.execute(
            "DELETE FROM upload_sessions
             WHERE (completed = 1 OR canceled = 1)
               AND id IN (
                 SELECT id FROM (
                   SELECT id,
                          ROW_NUMBER() OVER (
                            PARTITION BY workspace_id ORDER BY updated_at DESC, id DESC
                          ) AS retention_rank
                   FROM upload_sessions
                   WHERE completed = 1 OR canceled = 1
                 )
                 WHERE retention_rank > ?1
               )",
            [TERMINAL_UPLOAD_RETENTION_PER_WORKSPACE],
        )?;
        conn.execute_batch(
            "DELETE FROM mobile_offline_files
             WHERE file_id IN (SELECT id FROM files WHERE trashed != 0);
             DELETE FROM activity
             WHERE id IN (
               SELECT id FROM activity
               ORDER BY created_at DESC, id DESC
               LIMIT -1 OFFSET 100000
             );
             DELETE FROM sync_changes
             WHERE id IN (
               SELECT id FROM (
                 SELECT id,
                        ROW_NUMBER() OVER (
                          PARTITION BY workspace_id ORDER BY id DESC
                        ) AS retention_rank
                 FROM sync_changes
               )
               WHERE retention_rank > 10000
             );
             DELETE FROM sync_changes
             WHERE id IN (
               SELECT id FROM sync_changes ORDER BY id DESC LIMIT -1 OFFSET 100000
             );
             DELETE FROM email_outbox
             WHERE status <> 'queued' AND id IN (
               SELECT id FROM email_outbox WHERE status <> 'queued'
               ORDER BY updated_at DESC, id DESC LIMIT -1 OFFSET 10000
             );
             DELETE FROM import_runs
             WHERE status <> 'running' AND id IN (
               SELECT id FROM (
                 SELECT id,
                        ROW_NUMBER() OVER (
                          PARTITION BY workspace_id ORDER BY updated_at DESC, id DESC
                        ) AS retention_rank
                 FROM import_runs WHERE status <> 'running'
               )
               WHERE retention_rank > 1000
             );
             DELETE FROM import_runs
             WHERE status <> 'running' AND id IN (
               SELECT id FROM import_runs WHERE status <> 'running'
               ORDER BY updated_at DESC, id DESC LIMIT -1 OFFSET 10000
             );
             DELETE FROM office_edit_sessions
             WHERE used_at IS NOT NULL OR julianday(expires_at) <= julianday('now');",
        )?;
        conn.execute(
            "DELETE FROM mobile_offline_files
             WHERE (actor_email, file_id) IN (
               SELECT actor_email, file_id FROM (
                 SELECT actor_email, file_id,
                        ROW_NUMBER() OVER (
                          PARTITION BY actor_email ORDER BY marked_at DESC, file_id DESC
                        ) AS retention_rank
                 FROM mobile_offline_files
               )
               WHERE retention_rank > ?1
             )",
            [i64::try_from(super::MAX_FILE_TREE_NODES).unwrap_or(i64::MAX)],
        )?;
        Ok(())
    }
}

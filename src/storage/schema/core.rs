use rusqlite::Connection;

pub(super) fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                actor TEXT NOT NULL,
                target_id TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_receipts_created
                ON receipts(created_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_receipts_kind_created
                ON receipts(kind, created_at DESC, id DESC);

            CREATE TABLE IF NOT EXISTS activity (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                actor TEXT NOT NULL,
                target_id TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS retention_counters (
                name TEXT PRIMARY KEY,
                row_count INTEGER NOT NULL CHECK (row_count >= 0)
            );

            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                plan TEXT NOT NULL,
                billing_status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                name TEXT NOT NULL,
                storage_mode TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT,
                archived_at TEXT,
                FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_accounts (
                user_id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                totp_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                recovery_code_hashes TEXT NOT NULL DEFAULT '[]',
                totp_last_used_counter INTEGER,
                disabled_at TEXT,
                security_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                id TEXT PRIMARY KEY,
                actor_email TEXT NOT NULL,
                issuer TEXT NOT NULL,
                subject TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                publication_pending INTEGER NOT NULL DEFAULT 0
                    CHECK (publication_pending IN (0, 1)),
                client_ip TEXT,
                user_agent TEXT,
                last_seen_at TEXT
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                action TEXT NOT NULL,
                route TEXT NOT NULL,
                outcome TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                actor_email TEXT,
                credential_kind TEXT NOT NULL,
                credential_ref TEXT,
                session_id TEXT,
                client_ip TEXT,
                user_agent TEXT,
                target_ref TEXT,
                created_at TEXT NOT NULL,
                low_authority INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_security_events_created
                ON security_events(created_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_security_events_category_created
                ON security_events(category, created_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_security_events_outcome_created
                ON security_events(outcome, created_at DESC, id DESC);

            CREATE TABLE IF NOT EXISTS app_tokens (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                actor_email TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                workspace_ids_json TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                publication_pending INTEGER NOT NULL DEFAULT 0
                    CHECK (publication_pending IN (0, 1))
            );

            CREATE INDEX IF NOT EXISTS idx_app_tokens_actor_created
                ON app_tokens(actor_email, created_at);

            CREATE TABLE IF NOT EXISTS agent_principals (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL,
                creator_authority_kind TEXT NOT NULL DEFAULT 'user'
                    CHECK (creator_authority_kind IN ('user', 'operator', 'legacy_ambiguous')),
                delegation_parent_kind TEXT NOT NULL DEFAULT 'local'
                    CHECK (delegation_parent_kind IN ('local', 'external_sso')),
                disabled_at TEXT,
                created_at TEXT NOT NULL,
                publication_pending INTEGER NOT NULL DEFAULT 0
                    CHECK (publication_pending IN (0, 1))
            );

            CREATE TABLE IF NOT EXISTS agent_tokens (
                id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                delegation_kind TEXT NOT NULL DEFAULT 'folder'
                    CHECK (delegation_kind IN ('folder', 'delegated')),
                expires_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                publication_pending INTEGER NOT NULL DEFAULT 0
                    CHECK (publication_pending IN (0, 1)),
                FOREIGN KEY (principal_id) REFERENCES agent_principals(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_agent_tokens_principal_created
                ON agent_tokens(principal_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_agent_tokens_principal_active
                ON agent_tokens(principal_id) WHERE revoked_at IS NULL;

            CREATE INDEX IF NOT EXISTS idx_agent_principals_creator_id
                ON agent_principals(created_by, id);

            CREATE INDEX IF NOT EXISTS idx_agent_principals_active_creator_id
                ON agent_principals(created_by, id) WHERE disabled_at IS NULL;

            CREATE TABLE IF NOT EXISTS delegated_agent_parent_sessions (
                principal_id TEXT PRIMARY KEY,
                parent_session_id TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                issuer TEXT NOT NULL,
                subject TEXT NOT NULL,
                parent_token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (principal_id) REFERENCES agent_principals(id) ON DELETE CASCADE,
                FOREIGN KEY (parent_session_id) REFERENCES auth_sessions(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_delegated_agent_parent_sessions_parent
                ON delegated_agent_parent_sessions(parent_session_id, principal_id);

            CREATE TABLE IF NOT EXISTS auth_attempts (
                key TEXT PRIMARY KEY,
                actor_email TEXT,
                client_fingerprint TEXT,
                scope TEXT NOT NULL,
                failures INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_auth_attempts_updated
                ON auth_attempts(updated_at DESC, key ASC);

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_outbox (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                recipient_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body_text TEXT NOT NULL,
                -- NULL for account/global mail. Workspace fanout mail is
                -- accounted against its source workspace separately.
                workspace_id TEXT,
                delivery_class TEXT NOT NULL DEFAULT 'general',
                related_type TEXT,
                related_id TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sent_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_email_outbox_status_created
                ON email_outbox(status, created_at);

            CREATE TABLE IF NOT EXISTS server_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workspace_members (
                workspace_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                expires_at TEXT,
                PRIMARY KEY (workspace_id, user_id),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS workspace_invitations (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                invited_by TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                member_expires_in_seconds INTEGER,
                accepted_at TEXT,
                canceled_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                publication_pending INTEGER NOT NULL DEFAULT 0
                    CHECK (publication_pending IN (0, 1)),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS "groups" (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (group_id, user_id),
                FOREIGN KEY (group_id) REFERENCES "groups"(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS workspace_group_grants (
                workspace_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('viewer', 'editor')),
                created_at TEXT NOT NULL,
                PRIMARY KEY (workspace_id, group_id),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES "groups"(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                parent_id TEXT,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                revision INTEGER NOT NULL,
                trashed INTEGER NOT NULL,
                trashed_at TEXT,
                starred INTEGER NOT NULL DEFAULT 0,
                content_hash TEXT,
                content_bytes INTEGER NOT NULL DEFAULT 0,
                -- Custom folder cover image (Google-Drive style): the SHA-256 of
                -- a stored image blob shown as the folder's grid tile. NULL for
                -- files and for folders without a cover.
                cover_hash TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                -- Logical bytes charged for an active folder cover. This stays
                -- internal so quota accounting does not alter the file API.
                cover_bytes INTEGER NOT NULL DEFAULT 0,
                drop_inbox_owner_id TEXT,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_files_workspace_parent
                ON files(workspace_id, parent_id);
            -- Intentionally non-unique so legacy databases with duplicate paths
            -- still migrate; live PATCH destinations are guarded transactionally.
            CREATE INDEX IF NOT EXISTS idx_files_workspace_parent_name
                ON files(workspace_id, parent_id, name);
            CREATE INDEX IF NOT EXISTS idx_files_workspace_live_kind
                ON files(workspace_id, trashed, kind);
            CREATE INDEX IF NOT EXISTS idx_files_live_updated
                ON files(trashed, updated_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_workspace_members_actor_access
                ON workspace_members(user_id, workspace_id, role, expires_at);
            CREATE INDEX IF NOT EXISTS idx_group_members_actor_access
                ON group_members(user_id, group_id);
            CREATE INDEX IF NOT EXISTS idx_workspace_group_grants_access
                ON workspace_group_grants(group_id, workspace_id, role);
            CREATE INDEX IF NOT EXISTS idx_files_content_hash_referenced
                ON files(content_hash) WHERE content_hash IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_files_cover_hash_referenced
                ON files(cover_hash) WHERE cover_hash IS NOT NULL;

            CREATE TABLE IF NOT EXISTS agent_folder_grants (
                id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                root_file_id TEXT NOT NULL,
                permission TEXT NOT NULL CHECK (permission IN ('view', 'edit')),
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                created_by TEXT NOT NULL,
                creator_authority_kind TEXT NOT NULL DEFAULT 'user'
                    CHECK (creator_authority_kind IN ('user', 'operator', 'legacy_ambiguous')),
                created_at TEXT NOT NULL,
                publication_pending INTEGER NOT NULL DEFAULT 0
                    CHECK (publication_pending IN (0, 1)),
                FOREIGN KEY (principal_id) REFERENCES agent_principals(id) ON DELETE CASCADE,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (root_file_id) REFERENCES files(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_agent_grants_root_created
                ON agent_folder_grants(root_file_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_agent_grants_principal_created
                ON agent_folder_grants(principal_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_agent_grants_root_id
                ON agent_folder_grants(root_file_id, id);
            CREATE INDEX IF NOT EXISTS idx_agent_grants_principal_active_id
                ON agent_folder_grants(principal_id, id) WHERE revoked_at IS NULL;

            CREATE TABLE IF NOT EXISTS file_access_stats (
                file_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                access_count INTEGER NOT NULL DEFAULT 0 CHECK (access_count >= 0),
                download_count INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0),
                last_accessed_at TEXT,
                last_downloaded_at TEXT,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_file_access_stats_workspace
                ON file_access_stats(workspace_id);

            CREATE TABLE IF NOT EXISTS file_revisions (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                content_hash TEXT,
                content_bytes INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                conflict_of_revision INTEGER,
                conflict_of_file_id TEXT,
                pinned INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS file_text_index (
                file_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                source_revision INTEGER NOT NULL,
                source_content_hash TEXT NOT NULL,
                content_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS file_search_fts
            USING fts5(file_id UNINDEXED, workspace_id UNINDEXED, name, labels, metadata, content, tokenize='unicode61');

            CREATE TABLE IF NOT EXISTS file_metadata (
                file_id TEXT PRIMARY KEY,
                labels_json TEXT NOT NULL,
                custom_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );

            -- Both tables below are derived accounting. Backup V2 deliberately
            -- excludes them and rebuilds them from its authoritative tables.
            CREATE TABLE IF NOT EXISTS workspace_auxiliary_usage (
                workspace_id TEXT PRIMARY KEY,
                file_metadata_bytes INTEGER NOT NULL DEFAULT 0 CHECK (file_metadata_bytes >= 0),
                metadata_fts_projection_bytes INTEGER NOT NULL DEFAULT 0 CHECK (metadata_fts_projection_bytes >= 0),
                comment_reply_body_bytes INTEGER NOT NULL DEFAULT 0 CHECK (comment_reply_body_bytes >= 0),
                notification_bytes INTEGER NOT NULL DEFAULT 0 CHECK (notification_bytes >= 0),
                email_outbox_bytes INTEGER NOT NULL DEFAULT 0 CHECK (email_outbox_bytes >= 0),
                updated_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS workspace_auxiliary_metadata_fts_projection (
                file_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                projection_bytes INTEGER NOT NULL CHECK (projection_bytes >= 0),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_workspace_auxiliary_metadata_fts_workspace
                ON workspace_auxiliary_metadata_fts_projection(workspace_id);

            CREATE TABLE IF NOT EXISTS upload_sessions (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                actor_email TEXT NOT NULL DEFAULT 'system@local',
                parent_id TEXT,
                name TEXT NOT NULL,
                total_size INTEGER,
                received_bytes INTEGER NOT NULL,
                completed INTEGER NOT NULL,
                canceled INTEGER NOT NULL DEFAULT 0,
                file_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                canceled_at TEXT,
                path TEXT,
                -- Replacement intent is durable so a resumed session cannot
                -- lose its optimistic target. Both are NULL for new uploads.
                target_file_id TEXT,
                base_revision INTEGER,
                -- Links a completed session to its one terminal receipt so a
                -- retried final chunk is idempotent.
                completion_receipt_id TEXT,
                -- Snapshot used only for an idempotent stale-completion
                -- response; NULL for successful/new-file completions.
                completion_current_revision INTEGER,
                -- Quota capacity reserved at session admission. For a
                -- replacement this is only positive growth over the target's
                -- current body; staging capacity remains governed by
                -- `total_size` above.
                quota_reservation_bytes INTEGER NOT NULL DEFAULT 0,
                -- Selected behavior for a new-file collision at finalization.
                -- Replacement sessions always record `replace`.
                duplicate_policy TEXT NOT NULL DEFAULT 'keep_both',
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS sync_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (receipt_id) REFERENCES receipts(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_sync_changes_workspace_id
                ON sync_changes(workspace_id, id);

            CREATE TABLE IF NOT EXISTS sync_change_floors (
                workspace_id TEXT PRIMARY KEY,
                floor_cursor INTEGER NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS sync_change_counts (
                workspace_id TEXT PRIMARY KEY,
                retained_count INTEGER NOT NULL CHECK (retained_count >= 0),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            DROP TRIGGER IF EXISTS sync_changes_record_floor;
            DROP TRIGGER IF EXISTS sync_changes_bound_history;
            DROP TRIGGER IF EXISTS receipts_count_delete;
            DROP TRIGGER IF EXISTS receipts_bound_history;
            DROP TRIGGER IF EXISTS activity_count_delete;
            DROP TRIGGER IF EXISTS activity_bounded_retention;

            CREATE TRIGGER sync_changes_record_floor
            BEFORE DELETE ON sync_changes
            BEGIN
                INSERT INTO sync_change_floors (workspace_id, floor_cursor)
                VALUES (OLD.workspace_id, OLD.id)
                ON CONFLICT(workspace_id) DO UPDATE SET
                    floor_cursor = MAX(sync_change_floors.floor_cursor, excluded.floor_cursor);
                UPDATE sync_change_counts
                SET retained_count = MAX(0, retained_count - 1)
                WHERE workspace_id = OLD.workspace_id;
                DELETE FROM sync_change_counts
                WHERE workspace_id = OLD.workspace_id AND retained_count = 0;
                UPDATE retention_counters
                SET row_count = MAX(0, row_count - 1)
                WHERE name = 'sync_changes';
            END;

            CREATE TRIGGER sync_changes_bound_history
            AFTER INSERT ON sync_changes
            BEGIN
                INSERT INTO sync_change_counts (workspace_id, retained_count)
                VALUES (NEW.workspace_id, 1)
                ON CONFLICT(workspace_id) DO UPDATE SET
                    retained_count = sync_change_counts.retained_count + 1;
                INSERT INTO retention_counters (name, row_count)
                VALUES ('sync_changes', 1)
                ON CONFLICT(name) DO UPDATE SET row_count = row_count + 1;
                DELETE FROM sync_changes
                WHERE id = (
                    SELECT id FROM sync_changes WHERE workspace_id = NEW.workspace_id
                    ORDER BY id ASC LIMIT 1
                ) AND (
                    SELECT retained_count FROM sync_change_counts
                    WHERE workspace_id = NEW.workspace_id
                ) > 10000;
                DELETE FROM sync_changes
                WHERE id = (SELECT id FROM sync_changes ORDER BY id ASC LIMIT 1)
                  AND (
                    SELECT row_count FROM retention_counters
                    WHERE name = 'sync_changes'
                  ) > 100000;
            END;

            CREATE TRIGGER activity_count_delete
            BEFORE DELETE ON activity
            BEGIN
                UPDATE retention_counters
                SET row_count = MAX(0, row_count - 1)
                WHERE name = 'activity';
            END;

            CREATE TRIGGER activity_bounded_retention
            AFTER INSERT ON activity
            BEGIN
                INSERT INTO retention_counters (name, row_count)
                VALUES ('activity', 1)
                ON CONFLICT(name) DO UPDATE SET row_count = row_count + 1;
                DELETE FROM activity
                WHERE id = (
                    SELECT id FROM activity ORDER BY created_at ASC, id ASC LIMIT 1
                ) AND (
                    SELECT row_count FROM retention_counters WHERE name = 'activity'
                ) > 100000;
            END;

            DELETE FROM retention_counters;
            INSERT INTO retention_counters (name, row_count)
            VALUES
              ('receipts', (SELECT COUNT(*) FROM receipts)),
              ('activity', (SELECT COUNT(*) FROM activity)),
              ('sync_changes', (SELECT COUNT(*) FROM sync_changes));
            DELETE FROM sync_change_counts;
            INSERT INTO sync_change_counts (workspace_id, retained_count)
            SELECT workspace_id, COUNT(*) FROM sync_changes GROUP BY workspace_id;

            CREATE TABLE IF NOT EXISTS delta_sync_writes (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                actor_email TEXT NOT NULL,
                base_revision INTEGER NOT NULL,
                new_revision INTEGER NOT NULL,
                chunk_size INTEGER NOT NULL,
                chunks_total INTEGER NOT NULL,
                chunks_reused INTEGER NOT NULL,
                uploaded_bytes INTEGER NOT NULL,
                reconstructed_bytes INTEGER NOT NULL,
                content_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_delta_sync_writes_file_created
                ON delta_sync_writes(file_id, created_at);

            CREATE TABLE IF NOT EXISTS background_jobs (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                workspace_id TEXT,
                file_id TEXT,
                estimated_bytes INTEGER NOT NULL DEFAULT 1,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_background_jobs_status_created
                ON background_jobs(status, created_at);

            CREATE INDEX IF NOT EXISTS idx_background_jobs_status_workspace_created
                ON background_jobs(status, workspace_id, created_at, id);

            CREATE TABLE IF NOT EXISTS backup_jobs (
                id TEXT PRIMARY KEY,
                backup_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                format TEXT NOT NULL,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                actor TEXT NOT NULL,
                source_credential_kind TEXT,
                source_credential_id TEXT,
                source_credential_generation TEXT,
                archive_sha256 TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_backup_jobs_status_created
                ON backup_jobs(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_backup_jobs_backup_created
                ON backup_jobs(backup_id, created_at DESC);

            -- Local backup provenance is intentionally outside BACKUP_TABLES.
            -- Restoring an archive must never be able to replace the target
            -- instance's decision that a backup ID was managed locally.
            CREATE TABLE IF NOT EXISTS managed_backup_publications (
                backup_id TEXT PRIMARY KEY,
                archive_sha256 TEXT NOT NULL,
                published_at TEXT NOT NULL
            );

            -- Retired managed generations remain locally classified even if a
            -- backup-directory attacker restores an old archive and sidecar.
            -- Bound enforcement is transactional in Storage, where it can
            -- fail closed before destructive archive deletion.
            CREATE TABLE IF NOT EXISTS managed_backup_tombstones (
                backup_id TEXT PRIMARY KEY,
                retired_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_previews (
                file_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                kind TEXT NOT NULL,
                content TEXT NOT NULL,
                thumbnail_hash TEXT,
                thumbnail_content_type TEXT,
                thumbnail_bytes INTEGER NOT NULL DEFAULT 0,
                width INTEGER,
                height INTEGER,
                status TEXT NOT NULL DEFAULT 'ready',
                updated_at TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS mobile_offline_files (
                actor_email TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                marked_at TEXT NOT NULL,
                PRIMARY KEY (actor_email, file_id),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_mobile_offline_actor_workspace
                ON mobile_offline_files(actor_email, workspace_id, file_id);

            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                recipient_email TEXT NOT NULL,
                workspace_id TEXT,
                file_id TEXT,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                related_type TEXT,
                related_id TEXT,
                read_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_notifications_recipient_read_created
                ON notifications(recipient_email, read_at, created_at);
            CREATE INDEX IF NOT EXISTS idx_notifications_recipient_workspace_created
                ON notifications(recipient_email, workspace_id, created_at, id);

            CREATE TABLE IF NOT EXISTS office_edit_sessions (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                file_id TEXT NOT NULL,
                actor_email TEXT NOT NULL,
                base_revision INTEGER NOT NULL,
                provider_name TEXT NOT NULL,
                source_credential_kind TEXT NOT NULL DEFAULT 'legacy',
                source_credential_id TEXT,
                source_credential_generation TEXT,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS comments (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                author_email TEXT NOT NULL,
                body TEXT NOT NULL,
                resolved INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                edited_at TEXT,
                deleted_at TEXT,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS comment_replies (
                id TEXT PRIMARY KEY,
                comment_id TEXT NOT NULL,
                author_email TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                edited_at TEXT,
                deleted_at TEXT,
                FOREIGN KEY (comment_id) REFERENCES comments(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS folder_templates (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS folder_template_items (
                id TEXT PRIMARY KEY,
                template_id TEXT NOT NULL,
                path TEXT NOT NULL,
                kind TEXT NOT NULL,
                content TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (template_id) REFERENCES folder_templates(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS shares (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_required INTEGER NOT NULL DEFAULT 1,
                -- Nullable: NULL means the share never expires (permanent link).
                -- A positive `expires_in_seconds` stores a concrete RFC3339 time.
                expires_at TEXT,
                expires_in_seconds INTEGER,
                revoked INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                access_count INTEGER NOT NULL DEFAULT 0,
                last_accessed_at TEXT,
                target_kind TEXT NOT NULL DEFAULT 'file',
                allow_download INTEGER NOT NULL DEFAULT 1,
                recipient_note TEXT,
                max_uses INTEGER,
                publication_pending INTEGER NOT NULL DEFAULT 0
                    CHECK (publication_pending IN (0, 1)),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_shares_file_created
                ON shares(file_id, created_at DESC, id DESC);

            CREATE TABLE IF NOT EXISTS share_access_grants (
                token_hash TEXT PRIMARY KEY,
                share_id TEXT NOT NULL,
                authorization_fingerprint TEXT,
                client_fingerprint TEXT,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (share_id) REFERENCES shares(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_share_access_grants_share_expiry
                ON share_access_grants(share_id, expires_at);

            CREATE TABLE IF NOT EXISTS drops (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_required INTEGER NOT NULL DEFAULT 1,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                upload_count INTEGER NOT NULL DEFAULT 0,
                uploaded_bytes INTEGER NOT NULL DEFAULT 0,
                last_uploaded_at TEXT,
                publication_pending INTEGER NOT NULL DEFAULT 0
                    CHECK (publication_pending IN (0, 1)),
                inbox_file_id TEXT,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_drops_workspace_created
                ON drops(workspace_id, created_at DESC, id DESC);

            CREATE TABLE IF NOT EXISTS drop_upload_sessions (
                id TEXT PRIMARY KEY,
                drop_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                client_fingerprint TEXT NOT NULL,
                transport_fingerprint TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT,
                content_type TEXT,
                total_size INTEGER NOT NULL CHECK (total_size >= 0),
                received_bytes INTEGER NOT NULL DEFAULT 0 CHECK (received_bytes >= 0),
                chunk_count INTEGER NOT NULL DEFAULT 0 CHECK (chunk_count >= 0),
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'completed', 'canceled', 'failed')),
                file_id TEXT,
                last_error_code TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                canceled_at TEXT,
                FOREIGN KEY (drop_id) REFERENCES drops(id) ON DELETE CASCADE,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_drop_upload_sessions_drop_status
                ON drop_upload_sessions(drop_id, status, updated_at);
            CREATE INDEX IF NOT EXISTS idx_drop_upload_sessions_client_status
                ON drop_upload_sessions(drop_id, client_fingerprint, status);
            CREATE INDEX IF NOT EXISTS idx_drop_upload_sessions_status
                ON drop_upload_sessions(status, workspace_id, drop_id, total_size);

            CREATE TABLE IF NOT EXISTS workspace_policies (
                workspace_id TEXT PRIMARY KEY,
                quota_bytes INTEGER,
                public_links_enabled INTEGER NOT NULL DEFAULT 1,
                -- Passwordless share links are allowed by default (Google-Drive
                -- style one-click "Create link"). A workspace admin can still
                -- require a password via PATCH /workspaces/{id}/policy, which
                -- writes an explicit row with this flag set to 1.
                link_password_required INTEGER NOT NULL DEFAULT 0,
                -- Permanent links are an explicit policy choice. Fresh and
                -- migrated workspaces default to finite-only sharing.
                allow_never_expire INTEGER NOT NULL DEFAULT 0,
                max_link_ttl_seconds INTEGER NOT NULL DEFAULT 2592000,
                drop_password_required INTEGER NOT NULL DEFAULT 1,
                max_drop_ttl_seconds INTEGER NOT NULL DEFAULT 2592000,
                trash_retention_days INTEGER NOT NULL DEFAULT 30,
                revision_retention_days INTEGER NOT NULL DEFAULT 90,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS backup_policy (
                id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL,
                schedule TEXT NOT NULL,
                retention_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS support_bundles (
                id TEXT PRIMARY KEY,
                receipt_id TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                debug_export_bytes INTEGER NOT NULL,
                logs_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sandbox_profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                mode TEXT NOT NULL,
                data_dir TEXT NOT NULL,
                bind TEXT NOT NULL,
                service_user TEXT NOT NULL,
                service_group TEXT NOT NULL,
                read_write_paths_json TEXT NOT NULL,
                read_only_paths_json TEXT NOT NULL,
                network_policy TEXT NOT NULL,
                status TEXT NOT NULL,
                last_checked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS webdav_locks (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                resource_id TEXT,
                resource_path TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                scope TEXT NOT NULL CHECK (scope = 'exclusive'),
                depth TEXT NOT NULL CHECK (depth IN ('0', 'infinity')),
                token TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                timeout_seconds INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
                FOREIGN KEY (resource_id) REFERENCES files(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_webdav_locks_workspace_expiry
                ON webdav_locks(workspace_id, expires_at);
            CREATE INDEX IF NOT EXISTS idx_webdav_locks_resource
                ON webdav_locks(workspace_id, resource_id);
            "#,
        )?;
    Ok(())
}

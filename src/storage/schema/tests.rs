use crate::{
    model::{CreateFileRequest, FileKind},
    storage::Storage,
};

#[test]
fn migration_defaults_legacy_bearer_rows_to_published() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("drive.db");
    {
        let storage = Storage::open(path.clone()).unwrap();
        storage.migrate().unwrap();
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO auth_sessions (
                id, actor_email, issuer, subject, token_hash,
                expires_at, revoked_at, created_at
             ) VALUES (
                'legacy-bearer-session', 'legacy@example.test',
                'local-password', 'legacy-subject', 'legacy-session-hash',
                '2099-01-01T00:00:00Z', NULL, '2026-08-30T00:00:00Z'
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_tokens (
                id, label, actor_email, token_hash, workspace_ids_json,
                expires_at, last_used_at, revoked_at, created_at
             ) VALUES (
                'legacy-bearer-token', 'Legacy token', 'legacy@example.test',
                'legacy-token-hash', '[\"legacy-workspace\"]',
                '2099-01-01T00:00:00Z', NULL, NULL, '2026-08-30T00:00:00Z'
             )",
            [],
        )
        .unwrap();
    }

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "ALTER TABLE auth_sessions DROP COLUMN publication_pending;
             ALTER TABLE app_tokens DROP COLUMN publication_pending;",
        )
        .unwrap();
    }

    let storage = Storage::open(path).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    for table in ["auth_sessions", "app_tokens"] {
        let pending: i64 = conn
            .query_row(
                &format!("SELECT publication_pending FROM {table} LIMIT 1"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0, "legacy {table} credential must stay published");
    }
}

#[test]
fn migration_defaults_legacy_publication_resources_to_active_with_valid_state() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("drive.db");
    {
        let storage = Storage::open(path.clone()).unwrap();
        storage.migrate().unwrap();
        let (workspace, _, _) = storage
            .create_workspace("Legacy publication migration", "owner@example.test")
            .unwrap();
        let (file, _) = storage
            .create_file_with_content_bytes(
                CreateFileRequest {
                    workspace_id: workspace.id.clone(),
                    parent_id: None,
                    name: "legacy.txt".to_string(),
                    kind: FileKind::File,
                    content: None,
                    path: None,
                },
                Some("a".repeat(64)),
                1,
            )
            .unwrap();
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO agent_principals (
                id, name, created_by, creator_authority_kind, disabled_at, created_at
             ) VALUES (
                'legacy-agent-principal', 'Legacy agent', 'owner@example.test',
                'user', NULL, '2026-08-30T00:00:00Z'
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agent_tokens (
                id, principal_id, token_hash, expires_at, last_used_at, revoked_at, created_at
             ) VALUES (
                'legacy-agent-token', 'legacy-agent-principal', 'legacy-agent-token-hash',
                '2099-01-01T00:00:00Z', NULL, NULL, '2026-08-30T00:00:00Z'
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspace_invitations (
                id, workspace_id, email, role, token_hash, status, invited_by,
                expires_at, member_expires_in_seconds, accepted_at, canceled_at,
                created_at, updated_at
             ) VALUES (
                'legacy-invitation', ?1, 'invitee@example.test', 'viewer',
                'legacy-invitation-hash', 'pending', 'owner@example.test',
                '2099-01-01T00:00:00Z', NULL, NULL, NULL,
                '2026-08-30T00:00:00Z', '2026-08-30T00:00:00Z'
             )",
            [&workspace.id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agent_folder_grants (
                id, principal_id, workspace_id, root_file_id, permission, expires_at,
                revoked_at, created_by, creator_authority_kind, created_at
             ) VALUES (
                'legacy-agent-grant', 'legacy-agent-principal', ?1, ?2, 'view',
                '2099-01-01T00:00:00Z', NULL, 'owner@example.test', 'user',
                '2026-08-30T00:00:00Z'
             )",
            [&workspace.id, &file.id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO shares (
                id, file_id, password_hash, password_required, expires_at,
                expires_in_seconds, revoked, created_at
             ) VALUES (
                'legacy-share', ?1, 'legacy-share-password-hash', 1,
                '2099-01-01T00:00:00Z', 3600, 0, '2026-08-30T00:00:00Z'
             )",
            [&file.id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO drops (
                id, workspace_id, name, password_hash, expires_at, revoked, created_at
             ) VALUES (
                'legacy-drop', ?1, 'Legacy drop', 'legacy-drop-password-hash',
                '2099-01-01T00:00:00Z', 0, '2026-08-30T00:00:00Z'
             )",
            [&workspace.id],
        )
        .unwrap();
    }

    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "ALTER TABLE agent_principals DROP COLUMN publication_pending;
             ALTER TABLE agent_tokens DROP COLUMN publication_pending;
             ALTER TABLE agent_folder_grants DROP COLUMN publication_pending;
             ALTER TABLE workspace_invitations DROP COLUMN publication_pending;
             ALTER TABLE shares DROP COLUMN publication_pending;
             ALTER TABLE drops DROP COLUMN publication_pending;",
        )
        .unwrap();
    }

    let storage = Storage::open(path).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    for (table, id) in [
        ("agent_principals", "legacy-agent-principal"),
        ("agent_tokens", "legacy-agent-token"),
        ("agent_folder_grants", "legacy-agent-grant"),
        ("workspace_invitations", "legacy-invitation"),
        ("shares", "legacy-share"),
        ("drops", "legacy-drop"),
    ] {
        let pending: i64 = conn
            .query_row(
                &format!("SELECT publication_pending FROM {table} WHERE id = ?1"),
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0, "legacy {table} row must stay active");
        assert!(conn
            .execute(
                &format!("UPDATE {table} SET publication_pending = 2 WHERE id = ?1"),
                [id],
            )
            .is_err());
    }
}

#[test]
fn legacy_share_rebuild_retains_a_default_active_publication_state() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("drive.db");
    {
        let storage = Storage::open(path.clone()).unwrap();
        storage.migrate().unwrap();
        let (workspace, _, _) = storage
            .create_workspace("Legacy share rebuild", "owner@example.test")
            .unwrap();
        let (file, _) = storage
            .create_file_with_content_bytes(
                CreateFileRequest {
                    workspace_id: workspace.id,
                    parent_id: None,
                    name: "legacy-share.txt".to_string(),
                    kind: FileKind::File,
                    content: None,
                    path: None,
                },
                Some("b".repeat(64)),
                1,
            )
            .unwrap();
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO shares (
                id, file_id, password_hash, password_required, expires_at,
                expires_in_seconds, revoked, created_at
             ) VALUES (
                'legacy-rebuild-share', ?1, 'legacy-share-password-hash', 1,
                '2099-01-01T00:00:00Z', 3600, 0, '2026-08-30T00:00:00Z'
             )",
            [&file.id],
        )
        .unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TABLE share_access_grants;
             ALTER TABLE shares RENAME TO shares_migrate_old;
             CREATE TABLE shares (
                 id TEXT PRIMARY KEY,
                 file_id TEXT NOT NULL,
                 password_hash TEXT NOT NULL,
                 password_required INTEGER NOT NULL DEFAULT 1,
                 expires_at TEXT NOT NULL,
                 expires_in_seconds INTEGER,
                 revoked INTEGER NOT NULL,
                 created_at TEXT NOT NULL,
                 access_count INTEGER NOT NULL DEFAULT 0,
                 last_accessed_at TEXT,
                 target_kind TEXT NOT NULL DEFAULT 'file',
                 allow_download INTEGER NOT NULL DEFAULT 1,
                 recipient_note TEXT,
                 max_uses INTEGER,
                 FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
             );
             INSERT INTO shares (
                 id, file_id, password_hash, password_required, expires_at,
                 expires_in_seconds, revoked, created_at, access_count,
                 last_accessed_at, target_kind, allow_download, recipient_note, max_uses
             ) SELECT
                 id, file_id, password_hash, password_required, expires_at,
                 expires_in_seconds, revoked, created_at, access_count,
                 last_accessed_at, target_kind, allow_download, recipient_note, max_uses
             FROM shares_migrate_old;
             DROP TABLE shares_migrate_old;
             CREATE TABLE share_access_grants (
                 token_hash TEXT PRIMARY KEY,
                 share_id TEXT NOT NULL,
                 authorization_fingerprint TEXT,
                 client_fingerprint TEXT,
                 expires_at TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 FOREIGN KEY (share_id) REFERENCES shares(id) ON DELETE CASCADE
             );
             PRAGMA foreign_keys = ON;",
        )
        .unwrap();
    }

    let storage = Storage::open(path).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let (pending, expires_at_not_null): (i64, i64) = conn
        .query_row(
            "SELECT publication_pending,
                    (SELECT \"notnull\" FROM pragma_table_info('shares') WHERE name = 'expires_at')
             FROM shares WHERE id = 'legacy-rebuild-share'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(pending, 0);
    assert_eq!(expires_at_not_null, 0);
    assert!(conn
        .execute(
            "UPDATE shares SET publication_pending = 2 WHERE id = 'legacy-rebuild-share'",
            [],
        )
        .is_err());
}

#[test]
fn migration_adds_internal_low_authority_class_without_rewriting_history() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("drive.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE security_events (
             id TEXT PRIMARY KEY,
             category TEXT NOT NULL,
             action TEXT NOT NULL,
             route TEXT NOT NULL,
             outcome TEXT NOT NULL,
             status_code INTEGER NOT NULL,
             actor_email TEXT,
             credential_kind TEXT NOT NULL,
             session_id TEXT,
             client_ip TEXT,
             user_agent TEXT,
             target_ref TEXT,
             created_at TEXT NOT NULL
         );
         INSERT INTO security_events (
             id, category, action, route, outcome, status_code,
             actor_email, credential_kind, created_at
         ) VALUES (
             'legacy-event', 'command', 'POST', '/admin/test', 'success', 200,
             'admin@example.test', 'local_session', '2026-01-01T00:00:00Z'
         );",
    )
    .unwrap();
    drop(conn);

    let storage = Storage::open(path).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let legacy_class: i64 = conn
        .query_row(
            "SELECT low_authority FROM security_events WHERE id = 'legacy-event'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(legacy_class, 0);
}

#[test]
fn migration_places_legacy_drop_sessions_in_one_transport_partition() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("drive.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE drop_upload_sessions (
             id TEXT PRIMARY KEY,
             drop_id TEXT NOT NULL,
             workspace_id TEXT NOT NULL,
             client_fingerprint TEXT NOT NULL,
             name TEXT NOT NULL,
             path TEXT,
             content_type TEXT,
             total_size INTEGER NOT NULL,
             received_bytes INTEGER NOT NULL DEFAULT 0,
             chunk_count INTEGER NOT NULL DEFAULT 0,
             status TEXT NOT NULL DEFAULT 'active',
             file_id TEXT,
             last_error_code TEXT,
             created_at TEXT NOT NULL,
             updated_at TEXT NOT NULL,
             completed_at TEXT,
             canceled_at TEXT
         );
         INSERT INTO drop_upload_sessions (
             id, drop_id, workspace_id, client_fingerprint, name, total_size,
             status, created_at, updated_at
         ) VALUES (
             'legacy-session', 'legacy-drop', 'legacy-workspace',
             'caller-selected-proof', 'legacy.txt', 1, 'active',
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
         );",
    )
    .unwrap();
    drop(conn);

    let storage = Storage::open(path).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let transport: String = conn
        .query_row(
            "SELECT transport_fingerprint FROM drop_upload_sessions
             WHERE id = 'legacy-session'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let transport_index: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'index'
               AND name = 'idx_drop_upload_sessions_transport_status'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(transport, "legacy-transport-v1");
    assert_eq!(transport_index, 1);
}

#[test]
fn migration_discards_legacy_text_without_a_revision_and_hash_subject() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("drive.db");
    let storage = Storage::open(path.clone()).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Legacy search migration", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "memo.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some("a".repeat(64)),
            1,
        )
        .unwrap();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute_batch(
            "DROP TABLE file_text_index;
             CREATE TABLE file_text_index (
                 file_id TEXT PRIMARY KEY,
                 workspace_id TEXT NOT NULL,
                 content_text TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO file_text_index (file_id, workspace_id, content_text, updated_at)
             VALUES (?1, ?2, 'legacy-search-needle', '2026-01-01T00:00:00Z')",
            [&file.id, &workspace.id],
        )
        .unwrap();
        conn.execute(
            "UPDATE file_search_fts SET content = 'legacy-search-needle' WHERE file_id = ?1",
            [&file.id],
        )
        .unwrap();
    }
    drop(storage);

    let migrated = Storage::open(path).unwrap();
    migrated.migrate().unwrap();
    let conn = migrated.conn.lock().unwrap();
    let index_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_text_index WHERE file_id = ?1",
            [&file.id],
            |row| row.get(0),
        )
        .unwrap();
    let fts_content: String = conn
        .query_row(
            "SELECT content FROM file_search_fts WHERE file_id = ?1",
            [&file.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(index_rows, 0);
    assert_eq!(fts_content, "");
}

#[test]
fn migration_adds_nullable_totp_replay_counter_without_resetting_factor_state() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("drive.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE users (
             id TEXT PRIMARY KEY,
             email TEXT NOT NULL UNIQUE,
             created_at TEXT NOT NULL
         );
         CREATE TABLE auth_accounts (
             user_id TEXT PRIMARY KEY,
             email TEXT NOT NULL UNIQUE,
             password_hash TEXT NOT NULL,
             is_admin INTEGER NOT NULL DEFAULT 0,
             totp_secret TEXT,
             totp_enabled INTEGER NOT NULL DEFAULT 0,
             recovery_code_hashes TEXT NOT NULL DEFAULT '[]',
             disabled_at TEXT,
             security_version INTEGER NOT NULL DEFAULT 0,
             created_at TEXT NOT NULL,
             updated_at TEXT NOT NULL,
             FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
         );
         INSERT INTO users (id, email, created_at)
         VALUES ('legacy-user', 'legacy@example.test', '2026-01-01T00:00:00Z');
         INSERT INTO auth_accounts (
             user_id, email, password_hash, totp_secret, totp_enabled,
             recovery_code_hashes, created_at, updated_at
         ) VALUES (
             'legacy-user', 'legacy@example.test', 'legacy-hash',
             'LEGACY-TOTP-SECRET', 1, '[\"legacy-recovery-hash\"]',
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
         );",
    )
    .unwrap();
    drop(conn);

    let storage = Storage::open(path).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let (secret, enabled, counter): (Option<String>, i64, Option<i64>) = conn
        .query_row(
            "SELECT totp_secret, totp_enabled, totp_last_used_counter
             FROM auth_accounts WHERE email = 'legacy@example.test'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(secret.as_deref(), Some("LEGACY-TOTP-SECRET"));
    assert_eq!(enabled, 1);
    assert_eq!(counter, None);
}

#[test]
fn migration_adds_email_outbox_columns_before_publishing_workspace_index() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("drive.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE email_outbox (
             id TEXT PRIMARY KEY,
             kind TEXT NOT NULL,
             status TEXT NOT NULL,
             recipient_email TEXT NOT NULL,
             subject TEXT NOT NULL,
             body_text TEXT NOT NULL,
             related_type TEXT,
             related_id TEXT,
             attempts INTEGER NOT NULL DEFAULT 0,
             last_error TEXT,
             created_at TEXT NOT NULL,
             updated_at TEXT NOT NULL,
             sent_at TEXT
         );
         INSERT INTO email_outbox (
             id, kind, status, recipient_email, subject, body_text,
             attempts, created_at, updated_at
         ) VALUES (
             'legacy-email', 'account', 'queued', 'legacy@example.test',
             'Legacy subject', 'Legacy body', 0,
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
         );",
    )
    .unwrap();
    drop(conn);

    let storage = Storage::open(path).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let (workspace_id, delivery_class): (Option<String>, String) = conn
        .query_row(
            "SELECT workspace_id, delivery_class
             FROM email_outbox WHERE id = 'legacy-email'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let workspace_index: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'index' AND name = 'idx_email_outbox_workspace_created'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(workspace_id, None);
    assert_eq!(delivery_class, "general");
    assert_eq!(workspace_index, 1);
}

#[test]
fn referenced_hash_equality_queries_use_partial_indexes() {
    let data = tempfile::tempdir().unwrap();
    let storage = Storage::open(data.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    for (query, index) in [
        (
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM files WHERE content_hash = ?1",
            "idx_files_content_hash_referenced",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM files WHERE cover_hash = ?1",
            "idx_files_cover_hash_referenced",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM file_revisions WHERE content_hash = ?1",
            "idx_file_revisions_content_hash_referenced",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM file_previews WHERE thumbnail_hash = ?1",
            "idx_file_previews_thumbnail_hash_referenced",
        ),
    ] {
        let mut statement = conn.prepare(query).unwrap();
        let details = statement
            .query_map(["a"], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            details.iter().any(|detail| detail.contains(index)),
            "query plan for {index} did not use its partial index: {details:?}"
        );
        assert!(
            details
                .iter()
                .all(|detail| { !detail.contains("SCAN ") && !detail.contains("USE TEMP B-TREE") }),
            "query plan for {index} has a full scan or temp sort: {details:?}"
        );
    }
}

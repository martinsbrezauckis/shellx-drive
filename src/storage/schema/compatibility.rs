use rusqlite::Connection;

use super::super::{ensure_column, migrate_shares_expires_at_nullable};

mod agent_audit;
mod invitations;
mod shares;
mod uploads;

pub(super) fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    // New bearer issuances remain inactive until their terminal admin
    // revalidation commits. Existing credentials were already published, so
    // upgrade defaults must preserve their current usability.
    ensure_column(
        conn,
        "auth_sessions",
        "publication_pending",
        "publication_pending INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "app_tokens",
        "publication_pending",
        "publication_pending INTEGER NOT NULL DEFAULT 0",
    )?;
    // Publication-sensitive resources created by older binaries were already
    // returned to their callers. Their upgrade state must therefore stay
    // active rather than being quarantined as a new route-only intent.
    ensure_column(
        conn,
        "agent_tokens",
        "publication_pending",
        "publication_pending INTEGER NOT NULL DEFAULT 0 CHECK (publication_pending IN (0, 1))",
    )?;
    agent_audit::migrate(conn)?;
    ensure_column(
        conn,
        "agent_principals",
        "publication_pending",
        "publication_pending INTEGER NOT NULL DEFAULT 0 CHECK (publication_pending IN (0, 1))",
    )?;
    ensure_column(
        conn,
        "agent_folder_grants",
        "publication_pending",
        "publication_pending INTEGER NOT NULL DEFAULT 0 CHECK (publication_pending IN (0, 1))",
    )?;
    ensure_column(
        conn,
        "workspace_invitations",
        "publication_pending",
        "publication_pending INTEGER NOT NULL DEFAULT 0 CHECK (publication_pending IN (0, 1))",
    )?;
    invitations::cancel_orphaned_publications(conn)?;
    ensure_column(conn, "email_outbox", "workspace_id", "workspace_id TEXT")?;
    ensure_column(
        conn,
        "email_outbox",
        "delivery_class",
        "delivery_class TEXT NOT NULL DEFAULT 'general'",
    )?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_email_outbox_workspace_created
             ON email_outbox(workspace_id, created_at) WHERE workspace_id IS NOT NULL;",
    )?;
    super::super::email_outbox::migrate_queued_email_admission(conn)?;
    super::super::notifications::migrate_notification_retention(conn)?;
    conn.execute(
        "INSERT OR IGNORE INTO managed_backup_publications
            (backup_id, archive_sha256, published_at)
         SELECT jobs.backup_id, jobs.archive_sha256, jobs.updated_at
         FROM backup_jobs jobs
         WHERE jobs.kind = 'create'
           AND jobs.status = 'succeeded'
           AND jobs.archive_sha256 IS NOT NULL
           AND NOT EXISTS (
               SELECT 1 FROM managed_backup_tombstones tombstone
               WHERE tombstone.backup_id = jobs.backup_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM backup_jobs newer
               WHERE newer.backup_id = jobs.backup_id
                 AND newer.kind = 'create'
                 AND newer.status = 'succeeded'
                 AND newer.archive_sha256 IS NOT NULL
                 AND (newer.created_at, newer.id) > (jobs.created_at, jobs.id)
           )",
        [],
    )?;
    // Coalesce legacy queued duplicates before publishing the invariant used by
    // every enqueue path. A running job may still receive one queued successor
    // so a content mutation is never lost while derivation is in progress.
    conn.execute(
        "DELETE FROM background_jobs
         WHERE status = 'queued' AND file_id IS NOT NULL
           AND id NOT IN (
             SELECT MIN(id) FROM background_jobs
             WHERE status = 'queued' AND file_id IS NOT NULL
             GROUP BY kind, workspace_id, file_id
           )",
        [],
    )?;
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_background_jobs_one_queued_file_kind
             ON background_jobs(kind, workspace_id, file_id)
             WHERE status = 'queued' AND file_id IS NOT NULL;
         DELETE FROM background_jobs
         WHERE id IN (
           SELECT id FROM (
             SELECT id,
                    ROW_NUMBER() OVER (
                      PARTITION BY workspace_id
                      ORDER BY updated_at DESC, id DESC
                    ) AS terminal_rank
             FROM background_jobs
             WHERE status IN ('succeeded', 'failed', 'skipped')
           )
           WHERE terminal_rank > 1000
         );",
    )?;
    ensure_column(
        conn,
        "background_jobs",
        "estimated_bytes",
        "estimated_bytes INTEGER NOT NULL DEFAULT 1",
    )?;
    conn.execute(
        "UPDATE background_jobs
         SET estimated_bytes = 1
         WHERE estimated_bytes IS NULL OR estimated_bytes < 1",
        [],
    )?;
    // An upgraded instance can already hold a queue produced before pending
    // admission existed. Re-estimate its queued work from the current bounded
    // file body, then retain the oldest work within the same bounds applied to
    // every new enqueue. Per-workspace trimming comes first so one legacy
    // workspace cannot occupy the global queue after upgrade.
    crate::storage::background_jobs::bound_existing_queued_jobs(conn)?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_background_jobs_status_workspace_created
             ON background_jobs(status, workspace_id, created_at, id);",
    )?;
    ensure_column(conn, "workspaces", "updated_at", "updated_at TEXT")?;
    ensure_column(conn, "workspaces", "archived_at", "archived_at TEXT")?;
    ensure_column(conn, "workspaces", "tenant_id", "tenant_id TEXT")?;
    // Drive now has one ordinary, server-readable storage model. Preserve
    // the column for wire/database compatibility, but normalize databases
    // created while experimental alternate modes were accepted.
    conn.execute(
        "UPDATE workspaces SET storage_mode = 'open' WHERE storage_mode <> 'open'",
        [],
    )?;
    ensure_column(conn, "workspace_members", "expires_at", "expires_at TEXT")?;
    ensure_column(
        conn,
        "workspace_invitations",
        "member_expires_in_seconds",
        "member_expires_in_seconds INTEGER",
    )?;
    ensure_column(
        conn,
        "shares",
        "access_count",
        "access_count INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(conn, "shares", "last_accessed_at", "last_accessed_at TEXT")?;
    ensure_column(
        conn,
        "drops",
        "password_required",
        "password_required INTEGER",
    )?;
    let legacy_drop_passwords = {
        let mut stmt =
            conn.prepare("SELECT id, password_hash FROM drops WHERE password_required IS NULL")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (drop_id, password_hash) in legacy_drop_passwords {
        let password_required = !crate::auth::verify_password(&password_hash, "");
        conn.execute(
            "UPDATE drops SET password_required = ?2 WHERE id = ?1",
            rusqlite::params![drop_id, password_required as i64],
        )?;
    }
    ensure_column(
        conn,
        "shares",
        "password_required",
        "password_required INTEGER",
    )?;
    let legacy_passwords = {
        let mut stmt =
            conn.prepare("SELECT id, password_hash FROM shares WHERE password_required IS NULL")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (share_id, password_hash) in legacy_passwords {
        let password_required = !crate::auth::verify_password(&password_hash, "");
        conn.execute(
            "UPDATE shares SET password_required = ?2 WHERE id = ?1",
            rusqlite::params![share_id, password_required as i64],
        )?;
    }
    ensure_column(conn, "comments", "edited_at", "edited_at TEXT")?;
    ensure_column(conn, "comments", "deleted_at", "deleted_at TEXT")?;
    ensure_column(conn, "comment_replies", "updated_at", "updated_at TEXT")?;
    ensure_column(conn, "comment_replies", "edited_at", "edited_at TEXT")?;
    ensure_column(conn, "comment_replies", "deleted_at", "deleted_at TEXT")?;
    // Folder shares: distinguishes a file share from a folder-subtree share.
    // Nullable-safe default keeps every pre-existing share resolving as a
    // single-file share.
    ensure_column(
        conn,
        "shares",
        "target_kind",
        "target_kind TEXT NOT NULL DEFAULT 'file'",
    )?;
    ensure_column(
        conn,
        "shares",
        "allow_download",
        "allow_download INTEGER NOT NULL DEFAULT 1",
    )?;
    ensure_column(conn, "shares", "recipient_note", "recipient_note TEXT")?;
    ensure_column(conn, "shares", "max_uses", "max_uses INTEGER")?;
    ensure_column(
        conn,
        "share_access_grants",
        "client_fingerprint",
        "client_fingerprint TEXT",
    )?;
    ensure_column(
        conn,
        "workspace_policies",
        "allow_never_expire",
        "allow_never_expire INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "drops",
        "upload_count",
        "upload_count INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(conn, "drops", "last_uploaded_at", "last_uploaded_at TEXT")?;
    ensure_column(
        conn,
        "upload_sessions",
        "canceled",
        "canceled INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(conn, "upload_sessions", "canceled_at", "canceled_at TEXT")?;
    ensure_column(
        conn,
        "upload_sessions",
        "actor_email",
        "actor_email TEXT NOT NULL DEFAULT 'system@local'",
    )?;
    // Folder-upload structure: the relative `webkitRelativePath` captured at
    // session start, resolved into nested folders when the upload finishes.
    // Nullable so existing single-file sessions keep their `NULL` path.
    ensure_column(conn, "upload_sessions", "path", "path TEXT")?;
    ensure_column(
        conn,
        "upload_sessions",
        "target_file_id",
        "target_file_id TEXT",
    )?;
    ensure_column(
        conn,
        "upload_sessions",
        "base_revision",
        "base_revision INTEGER",
    )?;
    ensure_column(
        conn,
        "upload_sessions",
        "completion_receipt_id",
        "completion_receipt_id TEXT",
    )?;
    ensure_column(
        conn,
        "upload_sessions",
        "completion_current_revision",
        "completion_current_revision INTEGER",
    )?;
    ensure_column(
        conn,
        "upload_sessions",
        "quota_reservation_bytes",
        "quota_reservation_bytes INTEGER NOT NULL DEFAULT 0",
    )?;
    uploads::migrate(conn)?;
    // Sessions created before replacement support were all new-file uploads.
    // Preserve their original full-body reservation semantics.
    conn.execute(
        "UPDATE upload_sessions
         SET quota_reservation_bytes = CASE
             WHEN COALESCE(total_size, received_bytes) > 0
             THEN COALESCE(total_size, received_bytes)
             ELSE 1 END
         WHERE quota_reservation_bytes = 0
           AND target_file_id IS NULL",
        [],
    )?;
    // Replacement sessions created by the older delta-based admission logic
    // may reserve zero (or only growth bytes). Their old current body becomes
    // retained history, so the whole incoming body is additional quota.
    conn.execute(
        "UPDATE upload_sessions
         SET quota_reservation_bytes = CASE
             WHEN COALESCE(total_size, received_bytes) > 0
             THEN COALESCE(total_size, received_bytes)
             ELSE 1 END
         WHERE completed = 0
           AND canceled = 0
           AND target_file_id IS NOT NULL
           AND quota_reservation_bytes < CASE
               WHEN COALESCE(total_size, received_bytes) > 0
               THEN COALESCE(total_size, received_bytes)
               ELSE 1 END",
        [],
    )?;
    ensure_column(
        conn,
        "workspace_invitations",
        "expires_at",
        "expires_at TEXT",
    )?;
    conn.execute(
        "UPDATE workspace_invitations
         SET expires_at = updated_at
         WHERE expires_at IS NULL",
        [],
    )?;
    ensure_column(
        conn,
        "shares",
        "expires_in_seconds",
        "expires_in_seconds INTEGER",
    )?;
    // Never-expire shares store `expires_at = NULL`. DBs created before this
    // feature declared the column `TEXT NOT NULL`, which SQLite cannot relax
    // via `ALTER`, so rebuild the table when the constraint is still present.
    // Add every later defaultable column first so the rebuild can retain the
    // complete current share record rather than recalculating or dropping it.
    migrate_shares_expires_at_nullable(conn)?;
    // The nullable-expiry upgrade rebuilds `shares`. Add this field after that
    // legacy rebuild so it cannot be discarded from an upgraded table.
    ensure_column(
        conn,
        "shares",
        "publication_pending",
        "publication_pending INTEGER NOT NULL DEFAULT 0 CHECK (publication_pending IN (0, 1))",
    )?;
    ensure_column(
        conn,
        "drops",
        "publication_pending",
        "publication_pending INTEGER NOT NULL DEFAULT 0 CHECK (publication_pending IN (0, 1))",
    )?;
    // Delivery lifecycle predicates require the final Share/Drop/Invitation
    // publication schema. Run the scrub only after legacy Shares have been
    // rebuilt and every publication flag is present.
    super::super::email_outbox::purge_inactive_delivery_rows_locked(
        conn,
        &chrono::Utc::now().to_rfc3339(),
    )?;
    shares::migrate(conn)?;
    Ok(())
}

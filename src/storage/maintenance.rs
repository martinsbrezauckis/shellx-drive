use std::{fs, path::Path};

use rusqlite::{params, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    blob,
    error::ApiResult,
};

use super::{authorization, Storage};

const BACKFILL_BATCH_SIZE: usize = 1_000;
const RESET_ALL_SQL: &str = r#"
    DELETE FROM shares;
    DELETE FROM drop_upload_sessions;
    DELETE FROM drops;
    DELETE FROM folder_template_items;
    DELETE FROM folder_templates;
    DELETE FROM comment_replies;
    DELETE FROM comments;
    DELETE FROM office_edit_sessions;
    DELETE FROM notifications;
    DELETE FROM mobile_offline_files;
    DELETE FROM file_previews;
    DELETE FROM background_jobs;
    DELETE FROM delta_sync_writes;
    DELETE FROM upload_sessions;
    DELETE FROM webdav_locks;
    DELETE FROM file_search_fts;
    DELETE FROM file_metadata;
    DELETE FROM file_revisions;
    DELETE FROM files;
    DELETE FROM support_bundles;
    DELETE FROM import_runs;
    DELETE FROM backup_policy;
    DELETE FROM workspace_policies;
    DELETE FROM workspace_group_grants;
    DELETE FROM group_members;
    DELETE FROM workspace_invitations;
    DELETE FROM workspace_members;
    DELETE FROM "groups";
    DELETE FROM email_outbox;
    DELETE FROM password_reset_tokens;
    DELETE FROM server_settings;
    DELETE FROM auth_attempts;
    DELETE FROM app_tokens;
    DELETE FROM auth_sessions;
    DELETE FROM auth_accounts;
    DELETE FROM users;
    DELETE FROM sync_changes;
    DELETE FROM sync_change_floors;
    DELETE FROM sync_change_counts;
    DELETE FROM workspaces;
    DELETE FROM tenants;
    DELETE FROM receipts;
    DELETE FROM activity;
    DELETE FROM retention_counters;
"#;

impl Storage {
    pub fn reset_all(&self) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute_batch(RESET_ALL_SQL)
    }

    pub(crate) fn reset_all_authorized(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        tx.execute_batch(RESET_ALL_SQL)?;
        tx.commit()?;
        Ok(())
    }

    /// Reconcile logical cover charges for databases created before
    /// `files.cover_bytes` and for legacy backup restores. The immutable blob
    /// length, not imported metadata, is the quota authority.
    pub fn backfill_cover_bytes(&self, data_dir: &Path) -> ApiResult<()> {
        self.backfill_blob_bytes(
            data_dir,
            "SELECT id, cover_hash
             FROM files
             WHERE cover_hash IS NOT NULL
               AND (?1 IS NULL OR id > ?1)
             ORDER BY id ASC
             LIMIT ?2",
            "UPDATE files
             SET cover_bytes = ?1
             WHERE id = ?2 AND cover_hash = ?3 AND cover_bytes <> ?1",
            "cover byte reconciliation skipped historical cover blobs that are missing or invalid",
        )
    }

    /// Backfill thumbnail charges introduced with the derived-data budget so
    /// legacy zero values cannot bypass later workspace admission totals.
    pub fn backfill_thumbnail_bytes(&self, data_dir: &Path) -> ApiResult<()> {
        self.backfill_blob_bytes(
            data_dir,
            "SELECT file_id, thumbnail_hash
             FROM file_previews
             WHERE thumbnail_hash IS NOT NULL
               AND thumbnail_bytes = 0
               AND (?1 IS NULL OR file_id > ?1)
             ORDER BY file_id ASC
             LIMIT ?2",
            "UPDATE file_previews
             SET thumbnail_bytes = ?1
             WHERE file_id = ?2 AND thumbnail_hash = ?3 AND thumbnail_bytes = 0",
            "thumbnail byte backfill skipped historical preview blobs that are missing or invalid",
        )
    }

    /// Keyset-scan a legacy hash column in bounded batches and persist the
    /// corresponding on-disk blob length. Query strings are fixed internal
    /// constants from the two callers above, never external input.
    fn backfill_blob_bytes(
        &self,
        data_dir: &Path,
        select_sql: &str,
        update_sql: &str,
        warning: &'static str,
    ) -> ApiResult<()> {
        let mut after_id: Option<String> = None;
        let mut missing_or_invalid = 0_u64;
        loop {
            let candidates = {
                let conn = self.conn.lock().unwrap();
                let mut statement = conn.prepare(select_sql)?;
                let rows = statement
                    .query_map(params![after_id, BACKFILL_BATCH_SIZE as i64], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            if candidates.is_empty() {
                if missing_or_invalid > 0 {
                    tracing::warn!(missing_or_invalid, warning);
                }
                return Ok(());
            }
            for (id, hash) in &candidates {
                let bytes = blob::blob_file_path(data_dir, hash)
                    .ok()
                    .and_then(|path| fs::metadata(path).ok())
                    .filter(|metadata| metadata.file_type().is_file())
                    .and_then(|metadata| i64::try_from(metadata.len()).ok());
                if let Some(bytes) = bytes {
                    let conn = self.conn.lock().unwrap();
                    conn.execute(update_sql, params![bytes, id, hash])?;
                } else {
                    missing_or_invalid = missing_or_invalid.saturating_add(1);
                }
            }
            after_id = candidates.last().map(|(id, _)| id.clone());
        }
    }
}

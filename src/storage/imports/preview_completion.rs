use std::collections::HashSet;

use chrono::Utc;
use rusqlite::{params, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    download_subjects::FileContentSubject,
    error::{ApiError, ApiResult},
    model::Receipt,
};

use super::{ImportRunTotals, Storage};
use crate::storage::{
    authorization, file_access, insert_receipt_rows, new_receipt, FileAccessKind,
};

pub(crate) struct RcloneExportCompletion<'a> {
    pub run_id: &'a str,
    pub workspace_id: &'a str,
    pub file_ids: &'a [String],
    pub content_subjects: &'a [FileContentSubject],
    pub actor: &'a Actor,
    pub source_credential: &'a DriveCredential,
    pub totals: ImportRunTotals,
    pub statistics_targets: &'a [(String, String)],
}

impl Storage {
    /// Finish an export and its best-effort access counters under the same
    /// write transaction as the final credential and content-subject check.
    pub(crate) fn complete_rclone_export_authorized(
        &self,
        completion: RcloneExportCompletion<'_>,
    ) -> ApiResult<()> {
        let RcloneExportCompletion {
            run_id,
            workspace_id,
            file_ids,
            content_subjects,
            actor,
            source_credential,
            totals,
            statistics_targets,
        } = completion;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_download_ticket_authorized_in_tx(
            &tx,
            workspace_id,
            file_ids,
            content_subjects,
            actor,
            source_credential,
        )?;
        let changed = tx.execute(
            "UPDATE import_runs
             SET status = 'succeeded', entries = ?1, files = ?2, folders = ?3,
                 bytes = ?4, error_code = NULL, updated_at = ?5, completed_at = ?5
             WHERE id = ?6 AND kind = 'rclone_export' AND actor = ?7
               AND workspace_id = ?8 AND status = 'running'",
            params![
                totals.entries,
                totals.files,
                totals.folders,
                totals.bytes,
                now,
                run_id,
                &actor.email,
                workspace_id,
            ],
        )?;
        if changed != 1 {
            return Err(ApiError::Conflict);
        }

        if !statistics_targets.is_empty() {
            tx.execute_batch("SAVEPOINT rclone_export_stats")?;
            let mut unique = HashSet::with_capacity(statistics_targets.len());
            let mut statistics_error = None;
            for (file_id, target_workspace_id) in statistics_targets {
                if unique.insert(file_id.as_str()) {
                    if let Err(error) = file_access::record_one(
                        &tx,
                        file_id,
                        target_workspace_id,
                        FileAccessKind::Download,
                        &now,
                    ) {
                        statistics_error = Some(error);
                        break;
                    }
                }
            }
            if let Some(error) = statistics_error {
                tx.execute_batch("ROLLBACK TO rclone_export_stats; RELEASE rclone_export_stats")?;
                tracing::warn!(%error, "rclone export activity counter update failed");
            } else {
                tx.execute_batch("RELEASE rclone_export_stats")?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Atomically publish a successful preview and its receipt only while the
    /// originating credential still has workspace Write authority.
    pub(crate) fn complete_rclone_preview_authorized(
        &self,
        id: &str,
        workspace_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        totals: ImportRunTotals,
    ) -> ApiResult<Receipt> {
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("import.preview", &actor.email, Some(workspace_id));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_workspace_authorized(
            &tx,
            workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )?;
        let changed = tx.execute(
            "UPDATE import_runs
             SET status = 'succeeded', entries = ?1, files = ?2, folders = ?3,
                 bytes = ?4, error_code = NULL, updated_at = ?5, completed_at = ?5
             WHERE id = ?6 AND kind = 'rclone_preview' AND actor = ?7
               AND workspace_id = ?8 AND status = 'running'",
            params![
                totals.entries,
                totals.files,
                totals.folders,
                totals.bytes,
                now,
                id,
                &actor.email,
                workspace_id,
            ],
        )?;
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }
}

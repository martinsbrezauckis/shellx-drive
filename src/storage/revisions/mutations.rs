use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind, Receipt},
    workspace_policy::checked_retention_cutoff,
};

use super::{
    super::{
        background_jobs, enforce_quota_in_txn,
        human_item_grants::access::ensure_item_authorized_in_tx, insert_receipt_rows, new_receipt,
        refresh_file_search_index_locked, Storage,
    },
    RevisionPruneResult,
};

impl Storage {
    pub fn prune_file_revisions(
        &self,
        file_id: &str,
        actor: &str,
    ) -> ApiResult<RevisionPruneResult> {
        self.prune_file_revisions_inner(file_id, actor, None)
    }

    pub(crate) fn prune_file_revisions_authorized(
        &self,
        file_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<RevisionPruneResult> {
        self.prune_file_revisions_inner(file_id, &actor.email, Some((actor, source_credential)))
    }

    fn prune_file_revisions_inner(
        &self,
        file_id: &str,
        actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<RevisionPruneResult> {
        let receipt = new_receipt("file.revision.prune", actor, Some(file_id));
        let deleted = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (workspace_id, current_revision): (String, i64) = tx
                .query_row(
                    "SELECT workspace_id, revision FROM files WHERE id = ?1",
                    params![file_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                ensure_item_authorized_in_tx(
                    &tx,
                    file_id,
                    actor,
                    source_credential,
                    WorkspacePermission::Manage,
                )?;
            }
            let retention_days: i64 = tx
                .query_row(
                    "SELECT revision_retention_days FROM workspace_policies WHERE workspace_id = ?1",
                    params![&workspace_id],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or_else(|| {
                    super::super::default_workspace_policy(&workspace_id).revision_retention_days
                });
            let cutoff = checked_retention_cutoff(Utc::now(), retention_days)?.to_rfc3339();
            let candidates = {
                let mut stmt = tx.prepare(
                    "SELECT revision, content_hash, content_bytes
                     FROM file_revisions
                     WHERE file_id = ?1 AND revision != ?2 AND pinned = 0 AND created_at < ?3",
                )?;
                let rows = stmt.query_map(params![file_id, current_revision, &cutoff], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            let mut deleted = Vec::new();
            for candidate @ (revision, _, _) in candidates {
                if tx.execute(
                    "DELETE FROM file_revisions
                     WHERE file_id = ?1 AND revision = ?2 AND pinned = 0",
                    params![file_id, revision],
                )? == 1
                {
                    deleted.push(candidate);
                }
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            deleted
        };
        let deleted_bytes = deleted
            .iter()
            .fold(0_i64, |total, (_, _, bytes)| total.saturating_add(*bytes));
        let hashes = deleted
            .iter()
            .filter_map(|(_, hash, _)| hash.clone())
            .collect();
        Ok(RevisionPruneResult {
            deleted_revisions: deleted.len() as i64,
            deleted_content_bytes: deleted_bytes,
            revisions: self.list_file_revisions(file_id)?,
            candidate_hashes: hashes,
            receipt,
        })
    }

    pub fn restore_file_revision(
        &self,
        file_id: &str,
        revision: i64,
        actor: &str,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.restore_file_revision_inner(file_id, revision, actor, None)
    }

    pub(crate) fn restore_file_revision_authorized(
        &self,
        file_id: &str,
        revision: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.restore_file_revision_inner(
            file_id,
            revision,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn restore_file_revision_inner(
        &self,
        file_id: &str,
        revision: i64,
        actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(DriveFile, Receipt)> {
        let receipt = new_receipt("file.revision.restore", actor, Some(file_id));
        let file = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current = tx
                .query_row(
                    "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                            content_hash, created_at, updated_at, content_bytes, cover_hash
                     FROM files WHERE id = ?1",
                    params![file_id],
                    super::super::row_to_file,
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if let Some((actor, source_credential)) = authorization_context {
                ensure_item_authorized_in_tx(
                    &tx,
                    &current.id,
                    actor,
                    source_credential,
                    WorkspacePermission::Write,
                )?;
            }
            if !matches!(current.kind, FileKind::File) {
                return Err(ApiError::Validation(
                    "only regular files have restorable content revisions".to_string(),
                ));
            }
            let (content_hash, content_bytes): (Option<String>, i64) = tx
                .query_row(
                    "SELECT content_hash, content_bytes FROM file_revisions
                     WHERE file_id = ?1 AND revision = ?2",
                    params![file_id, revision],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            let content_hash = content_hash.ok_or_else(|| {
                ApiError::Validation("revision does not have restorable content".to_string())
            })?;
            let quota_bytes = tx
                .query_row(
                    "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                    params![&current.workspace_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            let next_revision = current.revision + 1;
            let updated_at = Utc::now().to_rfc3339();
            if let Some(quota_bytes) = quota_bytes {
                enforce_quota_in_txn(
                    &tx,
                    quota_bytes,
                    &current.workspace_id,
                    Some(file_id),
                    content_bytes,
                )?;
            }
            tx.execute(
                "UPDATE files
                 SET revision = ?1, content_hash = ?2, content_bytes = ?3, updated_at = ?4
                 WHERE id = ?5",
                params![
                    next_revision,
                    &content_hash,
                    content_bytes,
                    &updated_at,
                    file_id
                ],
            )?;
            tx.execute(
                "INSERT INTO file_revisions
                    (id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    file_id,
                    next_revision,
                    &content_hash,
                    content_bytes,
                    &updated_at,
                ],
            )?;
            let file = tx.query_row(
                "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                        content_hash, created_at, updated_at, content_bytes, cover_hash
                 FROM files WHERE id = ?1",
                params![file_id],
                super::super::row_to_file,
            )?;
            tx.execute(
                "DELETE FROM file_text_index WHERE file_id = ?1",
                params![file_id],
            )?;
            refresh_file_search_index_locked(&tx, file_id)?;
            let _ = background_jobs::enqueue_file_background_jobs_in_tx(&tx, &file)?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            file
        };
        Ok((file, receipt))
    }
}

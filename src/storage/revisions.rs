use rusqlite::{params, OptionalExtension, Row, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{FileRevision, Receipt},
};

use super::{
    human_item_grants::access::ensure_item_authorized_in_tx, insert_receipt_rows, new_receipt,
    Storage, MAX_DEBUG_LIST_ROWS, MAX_FILE_REVISIONS,
};

mod mutations;

pub struct RevisionPruneResult {
    pub deleted_revisions: i64,
    pub deleted_content_bytes: i64,
    pub revisions: Vec<FileRevision>,
    pub candidate_hashes: Vec<String>,
    pub receipt: Receipt,
}

impl Storage {
    pub fn list_file_revisions(&self, file_id: &str) -> ApiResult<Vec<FileRevision>> {
        self.get_file(file_id)?.ok_or(ApiError::NotFound)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT fr.file_id, fr.revision, fr.content_hash, fr.content_bytes,
                    fr.created_at, fr.conflict_of_revision, fr.pinned,
                    CASE WHEN fr.revision = f.revision THEN 1 ELSE 0 END
             FROM file_revisions fr
             JOIN files f ON f.id = fr.file_id
             WHERE fr.file_id = ?1
             ORDER BY fr.revision ASC, fr.created_at ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![file_id, (MAX_FILE_REVISIONS + 1) as i64],
            row_to_file_revision,
        )?;
        let revisions = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if revisions.len() > MAX_FILE_REVISIONS {
            return Err(ApiError::PayloadTooLarge(
                "file revision history exceeds its bounded limit".to_string(),
            ));
        }
        Ok(revisions)
    }

    pub fn file_revision_content_hash(
        &self,
        file_id: &str,
        revision: i64,
    ) -> ApiResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT content_hash FROM file_revisions WHERE file_id = ?1 AND revision = ?2",
                params![file_id, revision],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(crate) fn file_revision_content_descriptor(
        &self,
        file_id: &str,
        revision: i64,
    ) -> ApiResult<Option<(String, i64)>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT content_hash, content_bytes FROM file_revisions
                 WHERE file_id = ?1 AND revision = ?2",
                params![file_id, revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn list_all_file_revisions(&self) -> ApiResult<Vec<FileRevision>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT fr.file_id, fr.revision, fr.content_hash, fr.content_bytes,
                    fr.created_at, fr.conflict_of_revision, fr.pinned,
                    CASE WHEN fr.revision = f.revision THEN 1 ELSE 0 END
             FROM file_revisions fr
             JOIN files f ON f.id = fr.file_id
             ORDER BY fr.created_at ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([MAX_DEBUG_LIST_ROWS], row_to_file_revision)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn set_revision_pinned(
        &self,
        file_id: &str,
        revision: i64,
        pinned: bool,
        actor: &str,
    ) -> ApiResult<(Vec<FileRevision>, Receipt)> {
        self.set_revision_pinned_inner(file_id, revision, pinned, actor, None)
    }

    pub(crate) fn set_revision_pinned_authorized(
        &self,
        file_id: &str,
        revision: i64,
        pinned: bool,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Vec<FileRevision>, Receipt)> {
        self.set_revision_pinned_inner(
            file_id,
            revision,
            pinned,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn set_revision_pinned_inner(
        &self,
        file_id: &str,
        revision: i64,
        pinned: bool,
        actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(Vec<FileRevision>, Receipt)> {
        let kind = if pinned {
            "file.revision.pin"
        } else {
            "file.revision.unpin"
        };
        let receipt = new_receipt(kind, actor, Some(file_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let _workspace_id = tx
                .query_row(
                    "SELECT workspace_id FROM files WHERE id = ?1",
                    params![file_id],
                    |row| row.get::<_, String>(0),
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
            let changed = tx.execute(
                "UPDATE file_revisions SET pinned = ?1 WHERE file_id = ?2 AND revision = ?3",
                params![if pinned { 1 } else { 0 }, file_id, revision],
            )?;
            if changed == 0 {
                return Err(ApiError::NotFound);
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let revisions = self.list_file_revisions(file_id)?;
        Ok((revisions, receipt))
    }

    pub fn delete_file_revision(
        &self,
        file_id: &str,
        revision: i64,
        actor: &str,
    ) -> ApiResult<(Vec<FileRevision>, Vec<String>, Receipt)> {
        self.delete_file_revision_inner(file_id, revision, actor, None)
    }

    pub(crate) fn delete_file_revision_authorized(
        &self,
        file_id: &str,
        revision: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Vec<FileRevision>, Vec<String>, Receipt)> {
        self.delete_file_revision_inner(
            file_id,
            revision,
            &actor.email,
            Some((actor, source_credential)),
        )
    }

    fn delete_file_revision_inner(
        &self,
        file_id: &str,
        revision: i64,
        actor: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(Vec<FileRevision>, Vec<String>, Receipt)> {
        let receipt = new_receipt("file.revision.delete", actor, Some(file_id));
        let content_hash = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (_workspace_id, current_revision): (String, i64) = tx
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
                    WorkspacePermission::Write,
                )?;
            }
            if revision == current_revision {
                return Err(ApiError::Validation(
                    "the current revision cannot be deleted".to_string(),
                ));
            }
            let (content_hash, pinned) = tx
                .query_row(
                    "SELECT content_hash, pinned FROM file_revisions
                     WHERE file_id = ?1 AND revision = ?2",
                    params![file_id, revision],
                    |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)? != 0)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if pinned {
                return Err(ApiError::Validation(
                    "pinned revisions must be unpinned before deletion".to_string(),
                ));
            }
            if tx.execute(
                "DELETE FROM file_revisions WHERE file_id = ?1 AND revision = ?2 AND pinned = 0",
                params![file_id, revision],
            )? != 1
            {
                return Err(ApiError::NotFound);
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            content_hash
        };
        Ok((
            self.list_file_revisions(file_id)?,
            content_hash.into_iter().collect(),
            receipt,
        ))
    }
}

fn row_to_file_revision(row: &Row<'_>) -> rusqlite::Result<FileRevision> {
    let content_hash: Option<String> = row.get(2)?;
    let pinned: i64 = row.get(6)?;
    let current: i64 = row.get(7)?;
    Ok(FileRevision {
        file_id: row.get(0)?,
        revision: row.get(1)?,
        has_content: content_hash.is_some(),
        content_bytes: row.get(3)?,
        created_at: row.get(4)?,
        conflict_of_revision: row.get(5)?,
        pinned: pinned != 0,
        current: current != 0,
    })
}

#[cfg(test)]
mod tests;

use rusqlite::{params, OptionalExtension, Transaction};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{Receipt, StaleRevisionResponse},
    storage::{
        human_item_grants::access::resolve_item_response_access_in_tx, row_to_file, Storage,
    },
};

use super::{row_to_upload_session, CompletedUpload};

impl Storage {
    /// Return the immutable terminal outcome for a retried final chunk. No new
    /// revision, conflict file, or receipt is created on this path.
    pub fn completed_upload_outcome(&self, upload_id: &str) -> ApiResult<CompletedUpload> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let outcome = completed_upload_outcome_in_tx(&tx, upload_id, None)?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Recheck the current result file and source credential in the same
    /// snapshot that supplies a retried terminal response.
    pub(crate) fn completed_upload_outcome_authorized(
        &self,
        upload_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<CompletedUpload> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let outcome =
            completed_upload_outcome_in_tx(&tx, upload_id, Some((actor, source_credential)))?;
        tx.commit()?;
        Ok(outcome)
    }
}

fn completed_upload_outcome_in_tx(
    tx: &Transaction<'_>,
    upload_id: &str,
    authorization: Option<(&Actor, &DriveCredential)>,
) -> ApiResult<CompletedUpload> {
    let session = tx
            .query_row(
                "SELECT id, workspace_id, actor_email, parent_id, name, total_size, received_bytes, completed, canceled, file_id, created_at, updated_at, canceled_at, path,
                        target_file_id, base_revision, completion_receipt_id,
                        completion_current_revision, duplicate_policy
                 FROM upload_sessions WHERE id = ?1",
                params![upload_id],
                row_to_upload_session,
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
    if !session.completed {
        return Err(ApiError::Conflict);
    }
    let file_id = session.file_id.as_deref().ok_or(ApiError::Conflict)?;
    if let Some((actor, source_credential)) = authorization {
        if !actor.is_admin && session.actor_email != actor.email {
            return Err(ApiError::NotFound);
        }
        crate::storage::authorization::ensure_source_credential_active(
            tx,
            actor,
            source_credential,
        )?;
        resolve_item_response_access_in_tx(tx, file_id, actor, WorkspacePermission::Read)?;
    }
    let file = tx
        .query_row(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                        content_hash, created_at, updated_at, content_bytes, cover_hash
                 FROM files WHERE id = ?1",
            params![file_id],
            row_to_file,
        )
        .optional()?
        .ok_or(ApiError::NotFound)?;
    let receipt_id = session
        .completion_receipt_id
        .as_deref()
        .ok_or(ApiError::Conflict)?;
    let receipt = tx
        .query_row(
            "SELECT id, kind, actor, target_id, created_at FROM receipts WHERE id = ?1",
            params![receipt_id],
            |row| {
                Ok(Receipt {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    actor: row.get(2)?,
                    target_id: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        )
        .optional()?
        .ok_or(ApiError::Conflict)?;
    let conflict = match (&session.target_file_id, session.base_revision) {
        (Some(target_file_id), Some(base_revision)) if target_file_id != &file.id => {
            let current_revision = session
                .completion_current_revision
                .ok_or(ApiError::Conflict)?;
            Some(StaleRevisionResponse {
                error: "stale_revision",
                file_id: target_file_id.clone(),
                attempted_base_revision: base_revision,
                current_revision,
                conflict_file_id: file.id.clone(),
                receipt: receipt.clone(),
            })
        }
        _ => None,
    };
    Ok(CompletedUpload {
        session,
        file,
        receipt,
        conflict,
    })
}

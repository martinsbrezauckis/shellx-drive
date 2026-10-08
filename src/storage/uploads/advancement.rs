use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::UploadSession,
    storage::Storage,
};

use super::{admission::ensure_upload_finalizer_permission, row_to_upload_session};

impl Storage {
    pub fn update_upload_session_received_authorized(
        &self,
        upload_id: &str,
        expected_received_bytes: i64,
        received_bytes: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<UploadSession> {
        let updated_at = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = tx
            .query_row(
                "SELECT id, workspace_id, actor_email, parent_id, name, total_size,
                        received_bytes, completed, canceled, file_id, created_at, updated_at,
                        canceled_at, path, target_file_id, base_revision,
                        completion_receipt_id, completion_current_revision, duplicate_policy
                 FROM upload_sessions WHERE id = ?1",
                params![upload_id],
                row_to_upload_session,
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if !actor.is_admin && session.actor_email != actor.email {
            return Err(ApiError::NotFound);
        }
        ensure_upload_finalizer_permission(&tx, &session, actor, source_credential)?;
        if tx.execute(
            "UPDATE upload_sessions
             SET received_bytes = ?1, updated_at = ?2
             WHERE id = ?3 AND received_bytes = ?4
               AND completed = 0 AND canceled = 0",
            params![
                received_bytes,
                &updated_at,
                upload_id,
                expected_received_bytes
            ],
        )? != 1
        {
            return Err(ApiError::Conflict);
        }
        let session = tx.query_row(
            "SELECT id, workspace_id, actor_email, parent_id, name, total_size,
                    received_bytes, completed, canceled, file_id, created_at, updated_at,
                    canceled_at, path, target_file_id, base_revision,
                    completion_receipt_id, completion_current_revision, duplicate_policy
             FROM upload_sessions WHERE id = ?1",
            params![upload_id],
            row_to_upload_session,
        )?;
        tx.commit()?;
        Ok(session)
    }
}

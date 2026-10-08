use chrono::Utc;
use rusqlite::params;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{CommentThread, Receipt},
    storage::{insert_receipt_rows, new_receipt, Storage},
};

use super::super::{comment_file_id, ensure_comment_authorized};

impl Storage {
    pub fn resolve_comment(
        &self,
        comment_id: &str,
        actor_email: &str,
    ) -> ApiResult<(CommentThread, Receipt)> {
        self.resolve_comment_inner(comment_id, actor_email, None)
    }

    pub(crate) fn resolve_comment_authorized(
        &self,
        comment_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(CommentThread, Receipt)> {
        self.resolve_comment_inner(comment_id, &actor.email, Some((actor, source_credential)))
    }

    fn resolve_comment_inner(
        &self,
        comment_id: &str,
        actor_email: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(CommentThread, Receipt)> {
        let updated_at = Utc::now().to_rfc3339();
        let receipt = new_receipt("comment.resolve", actor_email, Some(comment_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let file_id = comment_file_id(&tx, comment_id)?;
            ensure_comment_authorized(&tx, &file_id, authorization_context)?;
            let updated = tx.execute(
                "UPDATE comments SET resolved = 1, updated_at = ?1 WHERE id = ?2 AND resolved = 0",
                params![&updated_at, comment_id],
            )?;
            if updated == 0 {
                return Err(ApiError::Conflict);
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let comment = self.get_comment(comment_id)?.ok_or(ApiError::NotFound)?;
        Ok((comment, receipt))
    }
}

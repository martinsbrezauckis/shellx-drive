use chrono::Utc;
use rusqlite::params;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{CommentReply, Receipt},
    storage::{
        auxiliary_storage::ensure_workspace_auxiliary_storage_delta_fits_in_tx,
        insert_receipt_rows, new_receipt, Storage,
    },
};

use super::super::{
    comment_reply_body_delta, ensure_comment_authorized,
    fanout::{
        fanout_delta_with_primary, persist_comment_fanout_in_tx, prepare_comment_fanout_in_tx,
        CommentFanoutNotice,
    },
    reply_file_id, validate_body,
};

impl Storage {
    pub fn update_comment_reply(
        &self,
        reply_id: &str,
        actor_email: &str,
        body: &str,
    ) -> ApiResult<(CommentReply, Receipt)> {
        self.update_comment_reply_inner(reply_id, actor_email, body, None)
    }

    pub(crate) fn update_comment_reply_authorized(
        &self,
        reply_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        body: &str,
    ) -> ApiResult<(CommentReply, Receipt)> {
        self.update_comment_reply_inner(
            reply_id,
            &actor.email,
            body,
            Some((actor, source_credential)),
        )
    }

    fn update_comment_reply_inner(
        &self,
        reply_id: &str,
        actor_email: &str,
        body: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(CommentReply, Receipt)> {
        let trimmed = validate_body(body, "reply")?;
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("comment.reply.update", actor_email, Some(reply_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let authorized_file_id = reply_file_id(&tx, reply_id)?;
            ensure_comment_authorized(&tx, &authorized_file_id, authorization_context)?;
            let (comment_id, previous_body, deleted_at): (String, String, Option<String>) = tx
                .query_row(
                    "SELECT comment_id, body, deleted_at FROM comment_replies WHERE id = ?1",
                    params![reply_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
            if deleted_at.is_some() {
                return Err(ApiError::Validation(
                    "deleted replies cannot be edited".to_string(),
                ));
            }
            let file_id: String = tx.query_row(
                "SELECT comments.file_id FROM comments
                 JOIN comment_replies ON comment_replies.comment_id = comments.id
                 WHERE comment_replies.id = ?1",
                params![reply_id],
                |row| row.get(0),
            )?;
            let workspace_id: String = tx.query_row(
                "SELECT workspace_id FROM files WHERE id = ?1",
                params![&file_id],
                |row| row.get(0),
            )?;
            let primary_delta = comment_reply_body_delta(&previous_body, trimmed, "reply")?;
            let fanout = authorization_context
                .is_some()
                .then(|| {
                    prepare_comment_fanout_in_tx(
                        &tx,
                        CommentFanoutNotice {
                            kind: "comment_reply_updated",
                            workspace_id: &workspace_id,
                            file_id: &file_id,
                            actor_email,
                            related_id: &comment_id,
                            verb: "edited a reply",
                            body: trimmed,
                        },
                    )
                })
                .transpose()?;
            let delta = fanout.as_ref().map_or(Ok(primary_delta), |fanout| {
                fanout_delta_with_primary(primary_delta, fanout)
            })?;
            ensure_workspace_auxiliary_storage_delta_fits_in_tx(&tx, &workspace_id, delta)?;
            tx.execute(
                "UPDATE comment_replies
                 SET body = ?1, updated_at = ?2, edited_at = ?2 WHERE id = ?3",
                params![trimmed, &now, reply_id],
            )?;
            if let Some(fanout) = fanout {
                persist_comment_fanout_in_tx(&tx, fanout)?;
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let reply = self
            .get_comment_reply(reply_id)?
            .ok_or(ApiError::NotFound)?;
        Ok((reply, receipt))
    }
}

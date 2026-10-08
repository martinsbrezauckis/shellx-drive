use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

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
    validate_body, MAX_REPLIES_PER_COMMENT, MAX_REPLIES_PER_FILE,
};

impl Storage {
    pub fn create_comment_reply(
        &self,
        comment_id: &str,
        author_email: &str,
        body: &str,
    ) -> ApiResult<(CommentReply, Receipt)> {
        self.create_comment_reply_inner(comment_id, author_email, body, None)
    }

    pub(crate) fn create_comment_reply_authorized(
        &self,
        comment_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        body: &str,
    ) -> ApiResult<(CommentReply, Receipt)> {
        self.create_comment_reply_inner(
            comment_id,
            &actor.email,
            body,
            Some((actor, source_credential)),
        )
    }

    fn create_comment_reply_inner(
        &self,
        comment_id: &str,
        author_email: &str,
        body: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(CommentReply, Receipt)> {
        let trimmed = validate_body(body, "reply")?;
        let now = Utc::now().to_rfc3339();
        let reply = CommentReply {
            id: Uuid::now_v7().to_string(),
            comment_id: comment_id.to_string(),
            author_email: author_email.to_string(),
            body: trimmed.to_string(),
            created_at: now.clone(),
            updated_at: now.clone(),
            edited_at: None,
            deleted_at: None,
        };
        let receipt = new_receipt("comment.reply", author_email, Some(&reply.id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let (file_id, deleted_at): (String, Option<String>) = tx
                .query_row(
                    "SELECT file_id, deleted_at FROM comments WHERE id = ?1",
                    params![comment_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if deleted_at.is_some() {
                return Err(ApiError::Validation(
                    "deleted comments cannot receive replies".to_string(),
                ));
            }
            let workspace_id: String = tx.query_row(
                "SELECT workspace_id FROM files WHERE id = ?1",
                params![&file_id],
                |row| row.get(0),
            )?;
            ensure_comment_authorized(&tx, &file_id, authorization_context)?;
            let comment_replies: i64 = tx.query_row(
                "SELECT COUNT(*) FROM comment_replies WHERE comment_id = ?1",
                params![comment_id],
                |row| row.get(0),
            )?;
            let file_replies: i64 = tx.query_row(
                "SELECT COUNT(*)
                 FROM comment_replies replies
                 JOIN comments ON comments.id = replies.comment_id
                 WHERE comments.file_id = ?1",
                params![&file_id],
                |row| row.get(0),
            )?;
            if comment_replies >= MAX_REPLIES_PER_COMMENT || file_replies >= MAX_REPLIES_PER_FILE {
                return Err(ApiError::PayloadTooLarge(
                    "this comment history reached its reply limit".to_string(),
                ));
            }
            let primary_delta = comment_reply_body_delta("", &reply.body, "reply")?;
            let fanout = authorization_context
                .is_some()
                .then(|| {
                    prepare_comment_fanout_in_tx(
                        &tx,
                        CommentFanoutNotice {
                            kind: "comment_reply",
                            workspace_id: &workspace_id,
                            file_id: &file_id,
                            actor_email: author_email,
                            related_id: &reply.id,
                            verb: "replied",
                            body: &reply.body,
                        },
                    )
                })
                .transpose()?;
            let delta = fanout.as_ref().map_or(Ok(primary_delta), |fanout| {
                fanout_delta_with_primary(primary_delta, fanout)
            })?;
            ensure_workspace_auxiliary_storage_delta_fits_in_tx(&tx, &workspace_id, delta)?;
            tx.execute(
                "INSERT INTO comment_replies
                    (id, comment_id, author_email, body, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![
                    &reply.id,
                    &reply.comment_id,
                    &reply.author_email,
                    &reply.body,
                    &reply.created_at,
                ],
            )?;
            if let Some(fanout) = fanout {
                persist_comment_fanout_in_tx(&tx, fanout)?;
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        Ok((reply, receipt))
    }
}

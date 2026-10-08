use chrono::Utc;
use rusqlite::params;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{CommentReply, Receipt},
    storage::{insert_receipt_rows, new_receipt, Storage},
};

use super::super::{
    ensure_comment_authorized,
    fanout::{try_persist_optional_delete_fanout_in_tx, CommentFanoutNotice},
    reply_file_id,
};

impl Storage {
    pub fn delete_comment_reply(
        &self,
        reply_id: &str,
        actor_email: &str,
    ) -> ApiResult<(CommentReply, Receipt)> {
        self.delete_comment_reply_inner(reply_id, actor_email, None)
    }

    pub(crate) fn delete_comment_reply_authorized(
        &self,
        reply_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(CommentReply, Receipt)> {
        self.delete_comment_reply_inner(reply_id, &actor.email, Some((actor, source_credential)))
    }

    fn delete_comment_reply_inner(
        &self,
        reply_id: &str,
        actor_email: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(CommentReply, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("comment.reply.delete", actor_email, Some(reply_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let authorized_file_id = reply_file_id(&tx, reply_id)?;
            ensure_comment_authorized(&tx, &authorized_file_id, authorization_context)?;
            let comment_id: String = tx.query_row(
                "SELECT comment_id FROM comment_replies WHERE id = ?1",
                params![reply_id],
                |row| row.get(0),
            )?;
            let file_id: String = tx.query_row(
                "SELECT file_id FROM comments WHERE id = ?1",
                params![&comment_id],
                |row| row.get(0),
            )?;
            let workspace_id: String = tx.query_row(
                "SELECT workspace_id FROM files WHERE id = ?1",
                params![&file_id],
                |row| row.get(0),
            )?;
            tx.execute(
                "UPDATE comment_replies
                 SET body = '', updated_at = ?1, deleted_at = COALESCE(deleted_at, ?1)
                 WHERE id = ?2",
                params![&now, reply_id],
            )?;
            if authorization_context.is_some() {
                try_persist_optional_delete_fanout_in_tx(
                    &tx,
                    &workspace_id,
                    CommentFanoutNotice {
                        kind: "comment_reply_deleted",
                        workspace_id: &workspace_id,
                        file_id: &file_id,
                        actor_email,
                        related_id: &comment_id,
                        verb: "removed a reply",
                        body: "",
                    },
                )?;
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

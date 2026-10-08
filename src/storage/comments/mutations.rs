use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{CommentThread, Receipt},
    storage::{
        auxiliary_storage::{
            ensure_workspace_auxiliary_storage_delta_fits_in_tx, project_comment_reply_body_storage,
        },
        insert_receipt_rows, new_receipt, Storage,
    },
};

use super::{
    comment_reply_body_delta, ensure_comment_authorized,
    fanout::{
        fanout_delta_with_primary, persist_comment_fanout_in_tx, prepare_comment_fanout_in_tx,
        try_persist_optional_delete_fanout_in_tx, CommentFanoutNotice,
    },
    validate_body, MAX_COMMENTS_PER_FILE,
};

impl Storage {
    pub fn create_comment(
        &self,
        file_id: &str,
        author_email: &str,
        body: &str,
    ) -> ApiResult<(CommentThread, Receipt)> {
        self.create_comment_inner(file_id, author_email, body, None)
    }

    pub(crate) fn create_comment_authorized(
        &self,
        file_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        body: &str,
    ) -> ApiResult<(CommentThread, Receipt)> {
        self.create_comment_inner(
            file_id,
            &actor.email,
            body,
            Some((actor, source_credential)),
        )
    }

    fn create_comment_inner(
        &self,
        file_id: &str,
        author_email: &str,
        body: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(CommentThread, Receipt)> {
        let trimmed = validate_body(body, "comment")?;
        let now = Utc::now().to_rfc3339();
        let comment_id = Uuid::now_v7().to_string();
        let receipt = new_receipt("comment.create", author_email, Some(&comment_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let workspace_id = tx
                .query_row(
                    "SELECT workspace_id FROM files WHERE id = ?1",
                    params![file_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            ensure_comment_authorized(&tx, file_id, authorization_context)?;
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM comments WHERE file_id = ?1",
                params![file_id],
                |row| row.get(0),
            )?;
            if count >= MAX_COMMENTS_PER_FILE {
                return Err(ApiError::PayloadTooLarge(format!(
                    "a file supports at most {MAX_COMMENTS_PER_FILE} comment threads"
                )));
            }
            let primary_delta = project_comment_reply_body_storage(trimmed, "comment")?;
            let fanout = authorization_context
                .is_some()
                .then(|| {
                    prepare_comment_fanout_in_tx(
                        &tx,
                        CommentFanoutNotice {
                            kind: "comment_created",
                            workspace_id: &workspace_id,
                            file_id,
                            actor_email: author_email,
                            related_id: &comment_id,
                            verb: "commented",
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
                "INSERT INTO comments (id, file_id, author_email, body, resolved, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
                params![&comment_id, file_id, author_email, trimmed, &now],
            )?;
            if let Some(fanout) = fanout {
                persist_comment_fanout_in_tx(&tx, fanout)?;
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let comment = self.get_comment(&comment_id)?.ok_or(ApiError::NotFound)?;
        Ok((comment, receipt))
    }

    pub fn update_comment(
        &self,
        comment_id: &str,
        actor_email: &str,
        body: &str,
    ) -> ApiResult<(CommentThread, Receipt)> {
        self.update_comment_inner(comment_id, actor_email, body, None)
    }

    pub(crate) fn update_comment_authorized(
        &self,
        comment_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        body: &str,
    ) -> ApiResult<(CommentThread, Receipt)> {
        self.update_comment_inner(
            comment_id,
            &actor.email,
            body,
            Some((actor, source_credential)),
        )
    }

    fn update_comment_inner(
        &self,
        comment_id: &str,
        actor_email: &str,
        body: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(CommentThread, Receipt)> {
        let trimmed = validate_body(body, "comment")?;
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("comment.update", actor_email, Some(comment_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let workspace_id = super::comment_workspace_id(&tx, comment_id)?;
            let authorized_file_id = super::comment_file_id(&tx, comment_id)?;
            ensure_comment_authorized(&tx, &authorized_file_id, authorization_context)?;
            let (previous_body, deleted_at): (String, Option<String>) = tx.query_row(
                "SELECT body, deleted_at FROM comments WHERE id = ?1",
                params![comment_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if deleted_at.is_some() {
                return Err(ApiError::Validation(
                    "deleted comments cannot be edited".to_string(),
                ));
            }
            let primary_delta = comment_reply_body_delta(&previous_body, trimmed, "comment")?;
            let file_id: String = tx.query_row(
                "SELECT file_id FROM comments WHERE id = ?1",
                params![comment_id],
                |row| row.get(0),
            )?;
            let fanout = authorization_context
                .is_some()
                .then(|| {
                    prepare_comment_fanout_in_tx(
                        &tx,
                        CommentFanoutNotice {
                            kind: "comment_updated",
                            workspace_id: &workspace_id,
                            file_id: &file_id,
                            actor_email,
                            related_id: comment_id,
                            verb: "edited a comment",
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
                "UPDATE comments SET body = ?1, updated_at = ?2, edited_at = ?2 WHERE id = ?3",
                params![trimmed, &now, comment_id],
            )?;
            if let Some(fanout) = fanout {
                persist_comment_fanout_in_tx(&tx, fanout)?;
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let comment = self.get_comment(comment_id)?.ok_or(ApiError::NotFound)?;
        Ok((comment, receipt))
    }

    pub fn delete_comment(
        &self,
        comment_id: &str,
        actor_email: &str,
    ) -> ApiResult<(CommentThread, Receipt)> {
        self.delete_comment_inner(comment_id, actor_email, None)
    }

    pub(crate) fn delete_comment_authorized(
        &self,
        comment_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(CommentThread, Receipt)> {
        self.delete_comment_inner(comment_id, &actor.email, Some((actor, source_credential)))
    }

    fn delete_comment_inner(
        &self,
        comment_id: &str,
        actor_email: &str,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<(CommentThread, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("comment.delete", actor_email, Some(comment_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let workspace_id = super::comment_workspace_id(&tx, comment_id)?;
            let authorized_file_id = super::comment_file_id(&tx, comment_id)?;
            ensure_comment_authorized(&tx, &authorized_file_id, authorization_context)?;
            let file_id: String = tx.query_row(
                "SELECT file_id FROM comments WHERE id = ?1",
                params![comment_id],
                |row| row.get(0),
            )?;
            tx.execute(
                "UPDATE comments
                 SET body = '', resolved = 1, updated_at = ?1, deleted_at = COALESCE(deleted_at, ?1)
                 WHERE id = ?2",
                params![&now, comment_id],
            )?;
            if authorization_context.is_some() {
                try_persist_optional_delete_fanout_in_tx(
                    &tx,
                    &workspace_id,
                    CommentFanoutNotice {
                        kind: "comment_deleted",
                        workspace_id: &workspace_id,
                        file_id: &file_id,
                        actor_email,
                        related_id: comment_id,
                        verb: "removed a comment",
                        body: "",
                    },
                )?;
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let comment = self.get_comment(comment_id)?.ok_or(ApiError::NotFound)?;
        Ok((comment, receipt))
    }
}

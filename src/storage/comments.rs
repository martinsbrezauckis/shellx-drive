mod fanout;
mod mutations;
mod reply_mutations;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use rusqlite::{params, params_from_iter, OptionalExtension, Row, ToSql};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{CommentReply, CommentThread},
};

use super::{
    auxiliary_storage::{
        project_comment_reply_body_storage, validate_comment_body_utf8,
        WorkspaceAuxiliaryStorageDelta,
    },
    human_item_grants::access::ensure_item_authorized_in_tx,
    Storage,
};

const MAX_COMMENTS_PER_FILE: i64 = 500;
const MAX_REPLIES_PER_COMMENT: i64 = 100;
const MAX_REPLIES_PER_FILE: i64 = 2_000;

impl Storage {
    pub fn list_comments_for_file(&self, file_id: &str) -> ApiResult<Vec<CommentThread>> {
        self.get_file(file_id)?.ok_or(ApiError::NotFound)?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(COMMENT_SELECT)?;
        let rows = stmt.query_map(params![file_id], row_to_comment_base)?;
        let bases = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        drop(conn);
        self.attach_file_replies(file_id, bases)
    }

    fn attach_file_replies(
        &self,
        file_id: &str,
        mut comments: Vec<CommentThread>,
    ) -> ApiResult<Vec<CommentThread>> {
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT replies.id, replies.comment_id, replies.author_email, replies.body,
                    replies.created_at, COALESCE(replies.updated_at, replies.created_at),
                    replies.edited_at, replies.deleted_at
             FROM comment_replies replies
             JOIN comments ON comments.id = replies.comment_id
             WHERE comments.file_id = ?1
             ORDER BY replies.created_at ASC, replies.id ASC
             LIMIT ?2",
        )?;
        let rows =
            statement.query_map(params![file_id, MAX_REPLIES_PER_FILE], row_to_comment_reply)?;
        let mut replies = HashMap::<String, Vec<CommentReply>>::new();
        for reply in rows {
            let reply = reply?;
            replies
                .entry(reply.comment_id.clone())
                .or_default()
                .push(reply);
        }
        for comment in &mut comments {
            comment.replies = replies.remove(&comment.id).unwrap_or_default();
        }
        Ok(comments)
    }

    pub fn get_comment(&self, comment_id: &str) -> ApiResult<Option<CommentThread>> {
        let conn = self.conn.lock().unwrap();
        let comment = conn
            .query_row(
                COMMENT_BY_ID_SELECT,
                params![comment_id],
                row_to_comment_base,
            )
            .optional()?;
        drop(conn);
        match comment {
            Some(comment) => Ok(self.attach_replies(vec![comment])?.into_iter().next()),
            None => Ok(None),
        }
    }

    pub fn get_comment_reply(&self, reply_id: &str) -> ApiResult<Option<CommentReply>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(REPLY_BY_ID_SELECT, params![reply_id], row_to_comment_reply)
            .optional()?)
    }

    pub fn list_debug_comments_bounded(
        &self,
        limit: usize,
        max_bytes: usize,
    ) -> ApiResult<(usize, usize, Vec<CommentThread>)> {
        let limit = limit.clamp(1, 200);
        let limit_i64 = i64::try_from(limit).expect("bounded comment limit");
        // Leave room for the response envelope and JSON array punctuation. Count
        // each row before retaining it, rather than materializing every body.
        let mut remaining = max_bytes.min(1024 * 1024).saturating_sub(4096);
        let conn = self.conn.lock().unwrap();
        let total_threads: usize =
            conn.query_row("SELECT COUNT(*) FROM comments", [], |row| row.get(0))?;
        let total_replies: usize =
            conn.query_row("SELECT COUNT(*) FROM comment_replies", [], |row| row.get(0))?;
        let mut stmt = conn.prepare(COMMENT_ALL_SELECT)?;
        let rows = stmt.query_map(params![limit_i64], row_to_comment_base)?;
        let mut comments = Vec::new();
        for row in rows {
            let comment = row?;
            let bytes = serde_json::to_vec(&comment)
                .expect("comment thread is JSON serializable")
                .len()
                + 1;
            if bytes <= remaining {
                remaining -= bytes;
                comments.push(comment);
            }
        }
        drop(stmt);
        if comments.is_empty() {
            return Ok((total_threads, total_replies, comments));
        }

        let placeholders = vec!["?"; comments.len()].join(",");
        let query = format!(
            "SELECT id, comment_id, author_email, body, created_at,
                    COALESCE(updated_at, created_at), edited_at, deleted_at
             FROM comment_replies WHERE comment_id IN ({placeholders})
             ORDER BY created_at DESC, id DESC LIMIT ?"
        );
        let mut parameters = comments
            .iter()
            .map(|comment| &comment.id as &dyn ToSql)
            .collect::<Vec<_>>();
        parameters.push(&limit_i64);
        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map(params_from_iter(parameters), row_to_comment_reply)?;
        let positions = comments
            .iter()
            .enumerate()
            .map(|(index, comment)| (comment.id.clone(), index))
            .collect::<HashMap<_, _>>();
        for row in rows {
            let reply = row?;
            let bytes = serde_json::to_vec(&reply)
                .expect("comment reply is JSON serializable")
                .len()
                + 1;
            if bytes <= remaining {
                remaining -= bytes;
                if let Some(&index) = positions.get(reply.comment_id.as_str()) {
                    comments[index].replies.push(reply);
                }
            }
        }
        for comment in &mut comments {
            comment.replies.sort_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then(left.id.cmp(&right.id))
            });
        }
        Ok((total_threads, total_replies, comments))
    }

    fn attach_replies(&self, mut comments: Vec<CommentThread>) -> ApiResult<Vec<CommentThread>> {
        for comment in &mut comments {
            comment.replies = self.list_replies_for_comment(&comment.id)?;
        }
        Ok(comments)
    }

    fn list_replies_for_comment(&self, comment_id: &str) -> ApiResult<Vec<CommentReply>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(REPLY_SELECT)?;
        let rows = stmt.query_map(params![comment_id], row_to_comment_reply)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

pub(super) fn ensure_comment_authorized(
    tx: &rusqlite::Transaction<'_>,
    file_id: &str,
    authorization_context: Option<(&Actor, &DriveCredential)>,
) -> ApiResult<()> {
    if let Some((actor, source_credential)) = authorization_context {
        ensure_item_authorized_in_tx(
            tx,
            file_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )?;
    }
    Ok(())
}

pub(super) fn comment_file_id(
    tx: &rusqlite::Transaction<'_>,
    comment_id: &str,
) -> ApiResult<String> {
    tx.query_row(
        "SELECT file_id FROM comments WHERE id = ?1",
        params![comment_id],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(ApiError::NotFound)
}

pub(super) fn reply_file_id(tx: &rusqlite::Transaction<'_>, reply_id: &str) -> ApiResult<String> {
    tx.query_row(
        "SELECT comments.file_id FROM comment_replies
         JOIN comments ON comments.id = comment_replies.comment_id
         WHERE comment_replies.id = ?1",
        params![reply_id],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(ApiError::NotFound)
}

pub(super) fn comment_workspace_id(
    tx: &rusqlite::Transaction<'_>,
    comment_id: &str,
) -> ApiResult<String> {
    tx.query_row(
        "SELECT files.workspace_id
         FROM comments JOIN files ON files.id = comments.file_id
         WHERE comments.id = ?1",
        params![comment_id],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(ApiError::NotFound)
}

const COMMENT_SELECT: &str =
    "SELECT id, file_id, author_email, body, resolved, created_at, updated_at, edited_at, deleted_at
     FROM comments WHERE file_id = ?1 ORDER BY created_at ASC LIMIT 500";
const COMMENT_BY_ID_SELECT: &str =
    "SELECT id, file_id, author_email, body, resolved, created_at, updated_at, edited_at, deleted_at
     FROM comments WHERE id = ?1";
const COMMENT_ALL_SELECT: &str =
    "SELECT id, file_id, author_email, body, resolved, created_at, updated_at, edited_at, deleted_at
     FROM comments ORDER BY created_at DESC, id DESC LIMIT ?1";
const REPLY_SELECT: &str = "SELECT id, comment_id, author_email, body, created_at,
            COALESCE(updated_at, created_at), edited_at, deleted_at
     FROM comment_replies WHERE comment_id = ?1 ORDER BY created_at ASC LIMIT 100";
const REPLY_BY_ID_SELECT: &str = "SELECT id, comment_id, author_email, body, created_at,
            COALESCE(updated_at, created_at), edited_at, deleted_at
     FROM comment_replies WHERE id = ?1";

pub(super) fn validate_body<'a>(body: &'a str, kind: &str) -> ApiResult<&'a str> {
    let trimmed = validate_comment_body_utf8(body, kind)?;
    if trimmed.chars().count() > 8_000 {
        return Err(ApiError::Validation(format!(
            "{kind} body must be 8000 characters or shorter"
        )));
    }
    Ok(trimmed)
}

pub(super) fn comment_reply_body_delta(
    previous: &str,
    next: &str,
    kind: &str,
) -> ApiResult<WorkspaceAuxiliaryStorageDelta> {
    let mut next_projection = if next.is_empty() {
        WorkspaceAuxiliaryStorageDelta::default()
    } else {
        project_comment_reply_body_storage(next, kind)?
    };
    let previous_bytes = i64::try_from(previous.len()).map_err(|_| {
        ApiError::Validation("comment/reply body length cannot be represented".to_string())
    })?;
    next_projection.comment_reply_body_bytes = next_projection
        .comment_reply_body_bytes
        .checked_sub(previous_bytes)
        .ok_or_else(|| ApiError::Validation("comment/reply body delta overflow".to_string()))?;
    Ok(next_projection)
}

fn row_to_comment_base(row: &Row<'_>) -> rusqlite::Result<CommentThread> {
    let resolved: i64 = row.get(4)?;
    Ok(CommentThread {
        id: row.get(0)?,
        file_id: row.get(1)?,
        author_email: row.get(2)?,
        body: row.get(3)?,
        resolved: resolved != 0,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        edited_at: row.get(7)?,
        deleted_at: row.get(8)?,
        replies: Vec::new(),
    })
}

fn row_to_comment_reply(row: &Row<'_>) -> rusqlite::Result<CommentReply> {
    Ok(CommentReply {
        id: row.get(0)?,
        comment_id: row.get(1)?,
        author_email: row.get(2)?,
        body: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        edited_at: row.get(6)?,
        deleted_at: row.get(7)?,
    })
}

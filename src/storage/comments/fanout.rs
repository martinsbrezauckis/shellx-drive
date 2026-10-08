use rusqlite::{params, Connection};

use crate::{
    error::{ApiError, ApiResult},
    model::Notification,
};

use super::super::{
    auxiliary_storage::{
        bounded_notice_snippet, bounded_notice_snippet_with_limit, project_notification_storage,
        WorkspaceAuxiliaryStorageDelta,
    },
    notifications::{
        build_notification, insert_notification_locked,
        list_active_workspace_notification_recipients_locked, reserve_notification_slot_locked,
    },
};

mod delete;

pub(super) use delete::try_persist_optional_delete_fanout_in_tx;

const NOTICE_TITLE_BYTES: usize = 512;
const NOTICE_MESSAGE_BYTES: usize = 2 * 1024;

pub(super) struct CommentFanoutNotice<'a> {
    pub(super) kind: &'a str,
    pub(super) workspace_id: &'a str,
    pub(super) file_id: &'a str,
    pub(super) actor_email: &'a str,
    pub(super) related_id: &'a str,
    pub(super) verb: &'a str,
    pub(super) body: &'a str,
}

pub(super) struct PreparedCommentFanout {
    entries: Vec<PreparedCommentFanoutEntry>,
    delta: WorkspaceAuxiliaryStorageDelta,
}

struct PreparedCommentFanoutEntry {
    notification: Notification,
}

/// Query recipients, make notification pruning part of the caller's mutation
/// transaction, and prepare bounded in-app delivery rows. Email delivery is
/// deliberately deferred: a captured or inactive mail queue must never block
/// an otherwise-authorized comment or reply.
pub(super) fn prepare_comment_fanout_in_tx(
    conn: &Connection,
    notice: CommentFanoutNotice<'_>,
) -> ApiResult<PreparedCommentFanout> {
    let file_name: String = conn
        .query_row(
            "SELECT name FROM files WHERE id = ?1 AND workspace_id = ?2",
            params![notice.file_id, notice.workspace_id],
            |row| row.get(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFound,
            other => ApiError::from(other),
        })?;
    let actor_email = notice.actor_email.trim().to_ascii_lowercase();
    let recipients =
        list_active_workspace_notification_recipients_locked(conn, notice.workspace_id)?
            .into_iter()
            .filter(|email| email != &actor_email)
            .collect::<Vec<_>>();
    let display_file_name = bounded_notice_snippet_with_limit(&file_name, NOTICE_TITLE_BYTES);
    let actor = bounded_notice_snippet_with_limit(notice.actor_email, NOTICE_TITLE_BYTES);
    let detail = bounded_notice_snippet(notice.body);
    let message = if detail.is_empty() {
        format!("{actor} {} on {display_file_name}", notice.verb)
    } else {
        format!("{actor} {} on {display_file_name}: {detail}", notice.verb)
    };
    let message = bounded_notice_snippet_with_limit(&message, NOTICE_MESSAGE_BYTES);
    let notification_title = bounded_notice_snippet_with_limit(
        &format!("Comment on {display_file_name}"),
        NOTICE_TITLE_BYTES,
    );
    let mut entries = Vec::with_capacity(recipients.len());
    let mut delta = WorkspaceAuxiliaryStorageDelta::default();
    for recipient_email in recipients {
        let notification = build_notification(
            &recipient_email,
            notice.kind,
            &notification_title,
            &message,
            Some(notice.workspace_id),
            Some(notice.file_id),
            Some("comment"),
            Some(notice.related_id),
        )?;
        // Do this before reservation so the ledger reflects the exact final
        // recipient inbox state, including replacement of an old entry.
        reserve_notification_slot_locked(conn, &notification)?;
        delta = add_delta(
            delta,
            project_notification_storage(&notification.title, &notification.body)?,
        )?;
        entries.push(PreparedCommentFanoutEntry { notification });
    }
    Ok(PreparedCommentFanout { entries, delta })
}

pub(super) fn fanout_delta_with_primary(
    primary: WorkspaceAuxiliaryStorageDelta,
    fanout: &PreparedCommentFanout,
) -> ApiResult<WorkspaceAuxiliaryStorageDelta> {
    add_delta(primary, fanout.delta)
}

pub(super) fn persist_comment_fanout_in_tx(
    conn: &Connection,
    fanout: PreparedCommentFanout,
) -> ApiResult<()> {
    for entry in fanout.entries {
        insert_notification_locked(conn, entry.notification)?;
    }
    Ok(())
}

fn add_delta(
    left: WorkspaceAuxiliaryStorageDelta,
    right: WorkspaceAuxiliaryStorageDelta,
) -> ApiResult<WorkspaceAuxiliaryStorageDelta> {
    Ok(WorkspaceAuxiliaryStorageDelta {
        file_metadata_bytes: checked_add(
            left.file_metadata_bytes,
            right.file_metadata_bytes,
            "file metadata",
        )?,
        metadata_fts_projection_bytes: checked_add(
            left.metadata_fts_projection_bytes,
            right.metadata_fts_projection_bytes,
            "metadata FTS projection",
        )?,
        comment_reply_body_bytes: checked_add(
            left.comment_reply_body_bytes,
            right.comment_reply_body_bytes,
            "comment/reply bodies",
        )?,
        notification_bytes: checked_add(
            left.notification_bytes,
            right.notification_bytes,
            "notifications",
        )?,
        email_outbox_bytes: checked_add(
            left.email_outbox_bytes,
            right.email_outbox_bytes,
            "workspace email outbox",
        )?,
    })
}

fn checked_add(left: i64, right: i64, label: &str) -> ApiResult<i64> {
    left.checked_add(right)
        .ok_or_else(|| ApiError::Validation(format!("{label} fanout delta overflow")))
}

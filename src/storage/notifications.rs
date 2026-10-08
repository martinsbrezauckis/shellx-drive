use chrono::Utc;
use rusqlite::params;
use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    model::Notification,
};

use super::{
    auxiliary_storage::{
        ensure_workspace_auxiliary_storage_delta_fits_in_tx, project_notification_storage,
    },
    normalize_storage_email, row_to_notification, Storage,
};

mod fanout;
mod read_state;
mod retention;
#[cfg(test)]
mod retention_tests;
mod visibility;
pub(super) use fanout::list_active_workspace_notification_recipients_locked;
pub(super) use retention::{migrate_notification_retention, reserve_notification_slot_locked};

const NOTIFICATION_LIST_LIMIT: i64 = 500;
const DEBUG_NOTIFICATION_LIST_LIMIT: i64 = 1_000;

impl Storage {
    #[allow(clippy::too_many_arguments)]
    pub fn create_notification(
        &self,
        recipient_email: &str,
        kind: &str,
        title: &str,
        body: &str,
        workspace_id: Option<&str>,
        file_id: Option<&str>,
        related_type: Option<&str>,
        related_id: Option<&str>,
    ) -> ApiResult<Notification> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let notification = build_notification(
            recipient_email,
            kind,
            title,
            body,
            workspace_id,
            file_id,
            related_type,
            related_id,
        )?;
        if let Some(workspace_id) = notification.workspace_id.as_deref() {
            reserve_notification_slot_locked(&tx, &notification)?;
            ensure_workspace_auxiliary_storage_delta_fits_in_tx(
                &tx,
                workspace_id,
                project_notification_storage(&notification.title, &notification.body)?,
            )?;
        }
        insert_notification_locked(&tx, notification.clone())?;
        tx.commit()?;
        Ok(notification)
    }

    pub fn list_notifications_for_actor(
        &self,
        recipient_email: &str,
        unread_only: bool,
    ) -> ApiResult<Vec<Notification>> {
        let recipient_email = normalize_storage_email(recipient_email)?;
        let conn = self.conn.lock().unwrap();
        let sql = if unread_only {
            "SELECT id, recipient_email, workspace_id, file_id, kind, title, body,
                    related_type, related_id, read_at, created_at
             FROM notifications
             WHERE recipient_email = ?1 AND read_at IS NULL
             ORDER BY created_at DESC, id DESC
             LIMIT ?2"
        } else {
            "SELECT id, recipient_email, workspace_id, file_id, kind, title, body,
                    related_type, related_id, read_at, created_at
             FROM notifications
             WHERE recipient_email = ?1
             ORDER BY created_at DESC, id DESC
             LIMIT ?2"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(
            params![recipient_email, NOTIFICATION_LIST_LIMIT],
            row_to_notification,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn unread_notification_count(&self, recipient_email: &str) -> ApiResult<i64> {
        let recipient_email = normalize_storage_email(recipient_email)?;
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM notifications WHERE recipient_email = ?1 AND read_at IS NULL",
            params![recipient_email],
            |row| row.get(0),
        )?)
    }

    pub fn list_notifications(&self) -> ApiResult<Vec<Notification>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, recipient_email, workspace_id, file_id, kind, title, body,
                    related_type, related_id, read_at, created_at
             FROM notifications ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![DEBUG_NOTIFICATION_LIST_LIMIT], row_to_notification)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

/// Insert one already validated notification in a caller-owned transaction.
/// The caller that knows all rows in a multi-row mutation must reserve its
/// exact workspace delta before invoking this helper. Standalone callers use
/// `create_notification`, which does that reservation itself.
pub(super) fn insert_notification_locked(
    conn: &rusqlite::Connection,
    notification: Notification,
) -> ApiResult<Notification> {
    reserve_notification_slot_locked(conn, &notification)?;
    conn.execute(
        "INSERT INTO notifications (
            id, recipient_email, workspace_id, file_id, kind, title, body,
            related_type, related_id, read_at, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10)",
        params![
            &notification.id,
            &notification.recipient_email,
            &notification.workspace_id,
            &notification.file_id,
            &notification.kind,
            &notification.title,
            &notification.body,
            &notification.related_type,
            &notification.related_id,
            &notification.created_at,
        ],
    )?;
    Ok(notification)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_notification(
    recipient_email: &str,
    kind: &str,
    title: &str,
    body: &str,
    workspace_id: Option<&str>,
    file_id: Option<&str>,
    related_type: Option<&str>,
    related_id: Option<&str>,
) -> ApiResult<Notification> {
    let recipient_email = normalize_storage_email(recipient_email)?;
    let kind = kind.trim();
    let title = title.trim();
    let body = body.trim();
    if kind.is_empty() || title.is_empty() || body.is_empty() {
        return Err(ApiError::Validation(
            "notification kind, title, and body are required".to_string(),
        ));
    }
    Ok(Notification {
        id: Uuid::now_v7().to_string(),
        recipient_email,
        workspace_id: workspace_id.map(str::to_string),
        file_id: file_id.map(str::to_string),
        kind: kind.to_string(),
        title: title.to_string(),
        body: body.to_string(),
        related_type: related_type.map(str::to_string),
        related_id: related_id.map(str::to_string),
        read_at: None,
        created_at: Utc::now().to_rfc3339(),
    })
}

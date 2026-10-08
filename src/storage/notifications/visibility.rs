use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::Notification,
};

use super::super::{
    authorization::ensure_source_credential_active,
    bounded_files::file_is_effectively_trashed_locked,
    human_item_grants::access::{ensure_item_authorized_in_tx, resolve_item_access_in_tx},
    normalize_storage_email, row_to_notification, Storage,
};

use super::NOTIFICATION_LIST_LIMIT;

const NOTIFICATION_SCAN_PAGE_SIZE: usize = 100;

pub(crate) struct VisibleNotificationList {
    pub(crate) notifications: Vec<Notification>,
    pub(crate) unread_count: i64,
}

impl Storage {
    /// Return inbox rows whose referenced authority is still current. The
    /// source credential and every row's current liveness are checked while a
    /// single immediate transaction holds the publication snapshot.
    pub(crate) fn list_notifications_visible_to_actor_with_credential(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
        unread_only: bool,
    ) -> ApiResult<VisibleNotificationList> {
        self.list_notifications_visible_in_tx(actor, Some(source_credential), unread_only)
    }

    #[cfg(test)]
    pub fn list_notifications_visible_to_actor(
        &self,
        actor: &Actor,
        unread_only: bool,
    ) -> ApiResult<Vec<Notification>> {
        Ok(self
            .list_notifications_visible_in_tx(actor, None, unread_only)?
            .notifications)
    }

    fn list_notifications_visible_in_tx(
        &self,
        actor: &Actor,
        source_credential: Option<&DriveCredential>,
        unread_only: bool,
    ) -> ApiResult<VisibleNotificationList> {
        let recipient_email = normalize_storage_email(&actor.email)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(source_credential) = source_credential {
            ensure_source_credential_active(&tx, actor, source_credential)?;
        }
        let now = Utc::now().to_rfc3339();
        let mut visible = Vec::with_capacity(NOTIFICATION_LIST_LIMIT as usize);
        let mut unread_count = 0;
        let mut cursor = None;
        loop {
            let notifications = list_recipient_notifications_page_in_tx(
                &tx,
                &recipient_email,
                unread_only,
                cursor.as_ref(),
            )?;
            let page_len = notifications.len();
            let next_cursor = notifications
                .last()
                .map(|notification| (notification.created_at.clone(), notification.id.clone()));
            for notification in notifications {
                if notification_is_live_in_tx(&tx, &notification, actor, source_credential, &now)? {
                    if notification.read_at.is_none() {
                        unread_count += 1;
                    }
                    if visible.len() < NOTIFICATION_LIST_LIMIT as usize {
                        visible.push(notification);
                    }
                }
            }
            if page_len < NOTIFICATION_SCAN_PAGE_SIZE {
                break;
            }
            cursor = next_cursor;
        }
        tx.commit()?;
        Ok(VisibleNotificationList {
            notifications: visible,
            unread_count,
        })
    }
}

pub(super) fn notification_is_live_in_tx(
    tx: &Transaction<'_>,
    notification: &Notification,
    actor: &Actor,
    source_credential: Option<&DriveCredential>,
    now: &str,
) -> ApiResult<bool> {
    if notification.related_type.as_deref() == Some("share") {
        return share_notification_is_live_in_tx(tx, notification, now);
    }
    let Some(file_id) = notification.file_id.as_deref() else {
        return Ok(true);
    };
    let result = match source_credential {
        Some(source_credential) => ensure_item_authorized_in_tx(
            tx,
            file_id,
            actor,
            source_credential,
            WorkspacePermission::Read,
        ),
        None => resolve_item_access_in_tx(tx, file_id, actor, WorkspacePermission::Read),
    };
    match result {
        Ok(_) => Ok(true),
        Err(ApiError::Forbidden | ApiError::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

/// A guest-share inbox row is live only while its exact published share/file
/// binding is redeemable and the target is live through its bounded parent
/// chain. This predicate is shared by list and saved-id read publication.
fn share_notification_is_live_in_tx(
    tx: &Transaction<'_>,
    notification: &Notification,
    now: &str,
) -> ApiResult<bool> {
    let (Some(share_id), Some(file_id)) = (
        notification.related_id.as_deref(),
        notification.file_id.as_deref(),
    ) else {
        return Ok(false);
    };
    let share_is_live = tx
        .query_row(
            "SELECT 1 FROM shares
             WHERE id = ?1 AND file_id = ?2
               AND publication_pending = 0 AND revoked = 0
               AND (expires_at IS NULL OR julianday(expires_at) > julianday(?3))
               AND (max_uses IS NULL OR access_count < max_uses)",
            params![share_id, file_id, now],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !share_is_live {
        return Ok(false);
    }
    match file_is_effectively_trashed_locked(tx, file_id) {
        Ok(trashed) => Ok(!trashed),
        Err(ApiError::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

fn list_recipient_notifications_page_in_tx(
    tx: &Transaction<'_>,
    recipient_email: &str,
    unread_only: bool,
    cursor: Option<&(String, String)>,
) -> ApiResult<Vec<Notification>> {
    let unread = if unread_only {
        " AND read_at IS NULL"
    } else {
        ""
    };
    let (sql, cursor) = if let Some((created_at, id)) = cursor {
        (
            format!(
                "SELECT id, recipient_email, workspace_id, file_id, kind, title, body,
                        related_type, related_id, read_at, created_at
                 FROM notifications
                 WHERE recipient_email = ?1{unread}
                   AND (created_at < ?2 OR (created_at = ?2 AND id < ?3))
                 ORDER BY created_at DESC, id DESC
                 LIMIT ?4"
            ),
            Some((created_at, id)),
        )
    } else {
        (
            format!(
                "SELECT id, recipient_email, workspace_id, file_id, kind, title, body,
                        related_type, related_id, read_at, created_at
                 FROM notifications
                 WHERE recipient_email = ?1{unread}
                 ORDER BY created_at DESC, id DESC
                 LIMIT ?2"
            ),
            None,
        )
    };
    let mut statement = tx.prepare(&sql)?;
    let rows = if let Some((created_at, id)) = cursor {
        statement.query_map(
            params![
                recipient_email,
                created_at,
                id,
                NOTIFICATION_SCAN_PAGE_SIZE as i64
            ],
            row_to_notification,
        )?
    } else {
        statement.query_map(
            params![recipient_email, NOTIFICATION_SCAN_PAGE_SIZE as i64],
            row_to_notification,
        )?
    };
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

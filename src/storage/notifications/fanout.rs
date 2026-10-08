use chrono::Utc;
use rusqlite::{params, Connection, TransactionBehavior};

use crate::{
    error::{ApiError, ApiResult},
    model::Notification,
};

use super::{
    build_notification, insert_notification_locked, project_notification_storage,
    reserve_notification_slot_locked, Storage,
};
use crate::storage::{
    auxiliary_storage::{
        ensure_workspace_auxiliary_storage_delta_fits_in_tx, WorkspaceAuxiliaryStorageDelta,
    },
    MAX_WORKSPACE_NOTIFICATION_RECIPIENTS,
};

impl Storage {
    /// Persist one workspace broadcast atomically. Callers that already
    /// committed the originating mutation may still treat this delivery as
    /// best-effort, but recipients must never observe a partial broadcast.
    #[allow(clippy::too_many_arguments)]
    pub fn notify_workspace_members(
        &self,
        workspace_id: &str,
        actor_email: &str,
        kind: &str,
        title: &str,
        body: &str,
        file_id: Option<&str>,
        related_type: Option<&str>,
        related_id: Option<&str>,
    ) -> ApiResult<Vec<Notification>> {
        let actor_email = actor_email.trim().to_ascii_lowercase();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let recipients = list_active_workspace_notification_recipients_locked(&tx, workspace_id)?;
        let notifications = recipients
            .into_iter()
            .filter(|email| email != &actor_email)
            .map(|email| {
                build_notification(
                    &email,
                    kind,
                    title,
                    body,
                    Some(workspace_id),
                    file_id,
                    related_type,
                    related_id,
                )
            })
            .collect::<ApiResult<Vec<_>>>()?;

        let mut notification_bytes = 0_i64;
        for notification in &notifications {
            reserve_notification_slot_locked(&tx, notification)?;
            let projected = project_notification_storage(&notification.title, &notification.body)?;
            notification_bytes = notification_bytes
                .checked_add(projected.notification_bytes)
                .ok_or_else(|| {
                    ApiError::Validation("workspace notification fanout overflow".to_string())
                })?;
        }
        ensure_workspace_auxiliary_storage_delta_fits_in_tx(
            &tx,
            workspace_id,
            WorkspaceAuxiliaryStorageDelta {
                notification_bytes,
                ..WorkspaceAuxiliaryStorageDelta::default()
            },
        )?;
        for notification in &notifications {
            insert_notification_locked(&tx, notification.clone())?;
        }
        tx.commit()?;
        Ok(notifications)
    }
}

pub(in crate::storage) fn list_active_workspace_notification_recipients_locked(
    conn: &Connection,
    workspace_id: &str,
) -> ApiResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT email FROM (
            SELECT u.email
            FROM workspace_members wm
            JOIN users u ON u.id = wm.user_id
            WHERE wm.workspace_id = ?1
              AND (wm.expires_at IS NULL OR wm.expires_at > ?2)
            UNION
            SELECT u.email
            FROM workspace_group_grants wgg
            JOIN group_members gm ON gm.group_id = wgg.group_id
            JOIN users u ON u.id = gm.user_id
            WHERE wgg.workspace_id = ?1
         )
         ORDER BY email ASC
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(
        params![
            workspace_id,
            Utc::now().to_rfc3339(),
            (MAX_WORKSPACE_NOTIFICATION_RECIPIENTS + 1) as i64,
        ],
        |row| row.get::<_, String>(0),
    )?;
    let recipients = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    if recipients.len() > MAX_WORKSPACE_NOTIFICATION_RECIPIENTS {
        return Err(ApiError::PayloadTooLarge(format!(
            "workspace notification fanout is limited to {MAX_WORKSPACE_NOTIFICATION_RECIPIENTS} recipients"
        )));
    }
    Ok(recipients)
}

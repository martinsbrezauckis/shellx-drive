use chrono::Utc;
use rusqlite::{params, Connection, TransactionBehavior};
use uuid::Uuid;

mod admission;
mod capture;
mod lifecycle;
#[cfg(test)]
mod tests;

use crate::{
    error::{ApiError, ApiResult},
    model::EmailOutboxItem,
};

use super::{
    auxiliary_storage::{
        ensure_workspace_auxiliary_storage_delta_fits_in_tx, project_workspace_email_outbox_storage,
    },
    normalize_storage_email, row_to_email_outbox_item, Storage, MAX_DEBUG_LIST_ROWS,
};

const MAX_TERMINAL_EMAIL_ROWS: i64 = 10_000;
const MAX_EMAIL_SUBJECT_BYTES: usize = 998;
pub(super) const MAX_EMAIL_BODY_BYTES: usize = 64 * 1024;

#[cfg(test)]
pub(super) use admission::MAX_QUEUED_EMAIL_ROWS;
pub(super) use admission::{migrate_queued_email_admission, EmailDeliveryClass};
pub(super) use lifecycle::{
    purge_inactive_delivery_rows_locked, purge_related_delivery_rows_locked,
};

impl Storage {
    pub fn queue_email(
        &self,
        kind: &str,
        recipient_email: &str,
        subject: &str,
        body_text: &str,
        related_type: Option<&str>,
        related_id: Option<&str>,
    ) -> ApiResult<EmailOutboxItem> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let item = insert_email_outbox_locked(
            &tx,
            EmailDeliveryClass::General,
            None,
            kind,
            recipient_email,
            subject,
            body_text,
            related_type,
            related_id,
        )?;
        tx.commit()?;
        Ok(item)
    }

    /// Queue mail that is explicitly attributable to one workspace. Account
    /// mail remains unattributed; workspace share, invitation, and fanout
    /// paths should use this method inside their own mutation transaction when
    /// they need to compose more than one source-row change.
    #[allow(clippy::too_many_arguments)]
    pub fn queue_workspace_email(
        &self,
        workspace_id: &str,
        kind: &str,
        recipient_email: &str,
        subject: &str,
        body_text: &str,
        related_type: Option<&str>,
        related_id: Option<&str>,
    ) -> ApiResult<EmailOutboxItem> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let delta = project_workspace_email_outbox_storage(subject.trim(), body_text)?;
        ensure_workspace_auxiliary_storage_delta_fits_in_tx(&tx, workspace_id, delta)?;
        let item = insert_email_outbox_locked(
            &tx,
            EmailDeliveryClass::Workspace,
            Some(workspace_id),
            kind,
            recipient_email,
            subject,
            body_text,
            related_type,
            related_id,
        )?;
        tx.commit()?;
        Ok(item)
    }

    pub fn list_email_outbox_redacted(&self) -> ApiResult<Vec<EmailOutboxItem>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, kind, status, recipient_email, subject, related_type,
                    related_id, attempts, last_error, created_at, updated_at, sent_at
             FROM email_outbox
             ORDER BY created_at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![MAX_DEBUG_LIST_ROWS], row_to_email_outbox_item)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn insert_email_outbox_locked(
    conn: &Connection,
    delivery_class: EmailDeliveryClass,
    workspace_id: Option<&str>,
    kind: &str,
    recipient_email: &str,
    subject: &str,
    body_text: &str,
    related_type: Option<&str>,
    related_id: Option<&str>,
) -> ApiResult<EmailOutboxItem> {
    if delivery_class == EmailDeliveryClass::Workspace && workspace_id.is_none() {
        return Err(ApiError::Validation(
            "workspace email delivery requires a workspace ID".to_string(),
        ));
    }
    if delivery_class != EmailDeliveryClass::Workspace && workspace_id.is_some() {
        return Err(ApiError::Validation(
            "non-workspace email delivery must not carry a workspace ID".to_string(),
        ));
    }
    let recipient_email = normalize_storage_email(recipient_email)?;
    let subject = subject.trim();
    if subject.is_empty() {
        return Err(ApiError::Validation(
            "email subject must not be empty".to_string(),
        ));
    }
    if subject.len() > MAX_EMAIL_SUBJECT_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "email subject exceeds {MAX_EMAIL_SUBJECT_BYTES} bytes"
        )));
    }
    if body_text.len() > MAX_EMAIL_BODY_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "email body exceeds {MAX_EMAIL_BODY_BYTES} bytes"
        )));
    }
    let now = Utc::now().to_rfc3339();
    purge_inactive_delivery_rows_locked(conn, &now)?;
    let item = EmailOutboxItem {
        id: Uuid::now_v7().to_string(),
        kind: kind.to_string(),
        status: "queued".to_string(),
        recipient_email,
        subject: subject.to_string(),
        related_type: related_type.map(str::to_string),
        related_id: related_id.map(str::to_string),
        attempts: 0,
        last_error: None,
        created_at: now.clone(),
        updated_at: now,
        sent_at: None,
    };
    conn.execute(
        "DELETE FROM email_outbox
         WHERE status <> 'queued' AND id NOT IN (
             SELECT id FROM email_outbox WHERE status <> 'queued'
             ORDER BY updated_at DESC, id DESC LIMIT ?1
         )",
        params![MAX_TERMINAL_EMAIL_ROWS],
    )?;
    admission::ensure_queued_email_capacity_locked(
        conn,
        delivery_class,
        workspace_id,
        &item.recipient_email,
    )?;
    conn.execute(
        "INSERT INTO email_outbox (
            id, kind, status, recipient_email, subject, body_text, workspace_id,
            delivery_class, related_type, related_id, attempts, last_error, created_at,
            updated_at, sent_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            &item.id,
            &item.kind,
            &item.status,
            &item.recipient_email,
            &item.subject,
            body_text,
            workspace_id,
            delivery_class.as_str(),
            &item.related_type,
            &item.related_id,
            item.attempts,
            &item.last_error,
            &item.created_at,
            &item.updated_at,
            &item.sent_at,
        ],
    )?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn insert_workspace_email_outbox_locked(
    conn: &Connection,
    workspace_id: &str,
    kind: &str,
    recipient_email: &str,
    subject: &str,
    body_text: &str,
    related_type: Option<&str>,
    related_id: Option<&str>,
) -> ApiResult<EmailOutboxItem> {
    let delta = project_workspace_email_outbox_storage(subject.trim(), body_text)?;
    ensure_workspace_auxiliary_storage_delta_fits_in_tx(conn, workspace_id, delta)?;
    insert_email_outbox_locked(
        conn,
        EmailDeliveryClass::Workspace,
        Some(workspace_id),
        kind,
        recipient_email,
        subject,
        body_text,
        related_type,
        related_id,
    )
}

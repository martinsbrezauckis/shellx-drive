use rusqlite::{params, Connection};

use crate::{error::ApiError, error::ApiResult};

pub(in super::super) const MAX_QUEUED_EMAIL_ROWS: i64 = 10_000;
const RESERVED_SECURITY_EMAIL_ROWS: i64 = 1_000;
const MAX_NON_SECURITY_QUEUED_EMAIL_ROWS: i64 =
    MAX_QUEUED_EMAIL_ROWS - RESERVED_SECURITY_EMAIL_ROWS;
pub(in super::super) const MAX_QUEUED_WORKSPACE_EMAIL_ROWS: i64 = 250;
pub(in super::super) const MAX_QUEUED_WORKSPACE_RECIPIENT_EMAIL_ROWS: i64 = 25;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum EmailDeliveryClass {
    /// Password/reset and account-security mail can use the installation-wide
    /// reserve that ordinary collaboration delivery may not consume.
    AccountSecurity,
    /// A durable workspace mutation caused this mail; it is charged and
    /// admitted against that workspace and recipient.
    Workspace,
    /// Legacy/general account mail remains non-security and cannot consume the
    /// security reserve.
    General,
}

impl EmailDeliveryClass {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::AccountSecurity => "account_security",
            Self::Workspace => "workspace",
            Self::General => "general",
        }
    }
}

pub(in super::super) fn ensure_queued_email_capacity_locked(
    conn: &Connection,
    delivery_class: EmailDeliveryClass,
    workspace_id: Option<&str>,
    recipient_email: &str,
) -> ApiResult<()> {
    if delivery_class == EmailDeliveryClass::Workspace {
        let workspace_id = workspace_id.expect("workspace delivery validated by caller");
        let workspace_queued: i64 = conn.query_row(
            "SELECT COUNT(*) FROM email_outbox
             WHERE status = 'queued' AND workspace_id = ?1",
            params![workspace_id],
            |row| row.get(0),
        )?;
        let recipient_queued: i64 = conn.query_row(
            "SELECT COUNT(*) FROM email_outbox
             WHERE status = 'queued' AND workspace_id = ?1 AND recipient_email = ?2",
            params![workspace_id, recipient_email],
            |row| row.get(0),
        )?;
        if workspace_queued >= MAX_QUEUED_WORKSPACE_EMAIL_ROWS
            || recipient_queued >= MAX_QUEUED_WORKSPACE_RECIPIENT_EMAIL_ROWS
        {
            return Err(ApiError::TooManyRequests);
        }
    }

    let queued: i64 = conn.query_row(
        "SELECT COUNT(*) FROM email_outbox WHERE status = 'queued'",
        [],
        |row| row.get(0),
    )?;
    if queued >= MAX_QUEUED_EMAIL_ROWS {
        return Err(ApiError::TooManyRequests);
    }
    if delivery_class != EmailDeliveryClass::AccountSecurity {
        let non_security_queued: i64 = conn.query_row(
            "SELECT COUNT(*) FROM email_outbox
             WHERE status = 'queued' AND delivery_class <> 'account_security'",
            [],
            |row| row.get(0),
        )?;
        if non_security_queued >= MAX_NON_SECURITY_QUEUED_EMAIL_ROWS {
            return Err(ApiError::TooManyRequests);
        }
    }
    Ok(())
}

/// Normalize legacy rows before new admission rules become authoritative.
/// Relationship-derived workspace rows are backfilled; rows with missing or
/// terminal sources are then removed by the normal lifecycle scrub.
pub(in super::super) fn migrate_queued_email_admission(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "UPDATE email_outbox
         SET delivery_class = 'account_security'
         WHERE kind = 'password_reset';
         UPDATE email_outbox
         SET workspace_id = (
             SELECT f.workspace_id FROM shares s JOIN files f ON f.id = s.file_id
             WHERE s.id = email_outbox.related_id
         )
         WHERE status = 'queued' AND workspace_id IS NULL
           AND related_type = 'share';
         UPDATE email_outbox
         SET workspace_id = (
             SELECT workspace_id FROM workspace_invitations wi
             WHERE wi.id = email_outbox.related_id
         )
         WHERE status = 'queued' AND workspace_id IS NULL
           AND related_type = 'workspace_invitation';
         UPDATE email_outbox
         SET delivery_class = 'workspace'
         WHERE status = 'queued' AND workspace_id IS NOT NULL;
         DELETE FROM email_outbox
         WHERE id IN (
             SELECT id FROM (
                 SELECT id, ROW_NUMBER() OVER (
                     PARTITION BY workspace_id
                     ORDER BY created_at DESC, id DESC
                 ) AS workspace_rank
                 FROM email_outbox
                 WHERE status = 'queued' AND workspace_id IS NOT NULL
             ) WHERE workspace_rank > 250
         );
         DELETE FROM email_outbox
         WHERE id IN (
             SELECT id FROM (
                 SELECT id, ROW_NUMBER() OVER (
                     PARTITION BY workspace_id, recipient_email
                     ORDER BY created_at DESC, id DESC
                 ) AS recipient_rank
                 FROM email_outbox
                 WHERE status = 'queued' AND workspace_id IS NOT NULL
             ) WHERE recipient_rank > 25
         );
         DELETE FROM email_outbox
         WHERE id IN (
             SELECT id FROM (
                 SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC, id DESC) AS queue_rank
                 FROM email_outbox
                 WHERE status = 'queued' AND delivery_class <> 'account_security'
             ) WHERE queue_rank > 9000
         );",
    )?;
    Ok(())
}

use chrono::{Duration, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission, WorkspaceRole},
    error::{ApiError, ApiResult},
    model::{Receipt, WorkspaceInvitation},
};

use super::{
    authorization,
    auxiliary_storage::{
        ensure_workspace_auxiliary_storage_delta_fits_in_tx, project_notification_storage,
    },
    email_outbox, ensure_pending_invitation_capacity, insert_receipt_rows,
    insert_workspace_email_outbox_locked, new_receipt, normalize_storage_email,
    notifications::{build_notification, insert_notification_locked},
    prune_workspace_invitation_history, row_to_workspace_invitation, Storage,
    WORKSPACE_INVITATION_TTL_DAYS,
};

fn validate_member_expiry(role: WorkspaceRole, seconds: Option<i64>) -> ApiResult<Option<i64>> {
    if role == WorkspaceRole::Owner && seconds.is_some() {
        return Err(ApiError::Validation(
            "workspace owners cannot have expiring access".to_string(),
        ));
    }
    if seconds.is_some_and(|value| !(3_600..=31_536_000).contains(&value)) {
        return Err(ApiError::Validation(
            "member expiry must be between 1 hour and 365 days".to_string(),
        ));
    }
    Ok(seconds)
}

impl Storage {
    /// Atomically replace or create an invitation and queue its matching token
    /// delivery only after the exact source credential and current Manage
    /// authority are revalidated in the same immediate transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn create_workspace_invitation(
        &self,
        workspace_id: &str,
        email: &str,
        role: WorkspaceRole,
        member_expires_in_seconds: Option<i64>,
        token_hash: &str,
        email_body: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(WorkspaceInvitation, Receipt)> {
        self.workspace_storage_mode(workspace_id)?;
        let email = normalize_storage_email(email)?;
        let member_expires_in_seconds = validate_member_expiry(role, member_expires_in_seconds)?;
        let now = Utc::now().to_rfc3339();
        let expires_at = (Utc::now() + Duration::days(WORKSPACE_INVITATION_TTL_DAYS)).to_rfc3339();
        let mut invitation = WorkspaceInvitation {
            id: Uuid::now_v7().to_string(),
            workspace_id: workspace_id.to_string(),
            email,
            role: role.as_db_str().to_string(),
            status: "pending".to_string(),
            invited_by: actor.email.clone(),
            expires_at,
            member_expires_in_seconds,
            accepted_at: None,
            canceled_at: None,
            created_at: now.clone(),
            updated_at: now,
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_workspace_authorized(
            &tx,
            workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Manage,
        )?;
        prune_workspace_invitation_history(&tx, workspace_id)?;
        let existing = tx
            .query_row(
                "SELECT id, created_at FROM workspace_invitations
                 WHERE workspace_id = ?1 AND email = ?2 AND status = 'pending'
                   AND publication_pending = 0
                 ORDER BY updated_at DESC, id DESC LIMIT 1",
                params![workspace_id, &invitation.email],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((id, created_at)) = existing {
            invitation.id = id;
            invitation.created_at = created_at;
            let changed = tx.execute(
                "UPDATE workspace_invitations
                 SET role = ?1, token_hash = ?2, invited_by = ?3, expires_at = ?4,
                     accepted_at = NULL, canceled_at = NULL, updated_at = ?5,
                     member_expires_in_seconds = ?6
                 WHERE id = ?7 AND workspace_id = ?8 AND status = 'pending'
                   AND publication_pending = 0",
                params![
                    &invitation.role,
                    token_hash,
                    &invitation.invited_by,
                    &invitation.expires_at,
                    &invitation.updated_at,
                    invitation.member_expires_in_seconds,
                    &invitation.id,
                    workspace_id,
                ],
            )?;
            if changed != 1 {
                return Err(ApiError::Conflict);
            }
            email_outbox::purge_related_delivery_rows_locked(
                &tx,
                "workspace_invitation",
                &invitation.id,
            )?;
        } else {
            ensure_pending_invitation_capacity(&tx, workspace_id)?;
            tx.execute(
                "INSERT INTO workspace_invitations (
                    id, workspace_id, email, role, token_hash, status, invited_by,
                    expires_at, accepted_at, canceled_at, created_at, updated_at,
                    member_expires_in_seconds
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    &invitation.id,
                    &invitation.workspace_id,
                    &invitation.email,
                    &invitation.role,
                    token_hash,
                    &invitation.status,
                    &invitation.invited_by,
                    &invitation.expires_at,
                    &invitation.accepted_at,
                    &invitation.canceled_at,
                    &invitation.created_at,
                    &invitation.updated_at,
                    invitation.member_expires_in_seconds,
                ],
            )?;
        }
        queue_invitation_delivery(&tx, workspace_id, &invitation, email_body)?;
        let receipt = new_receipt(
            "workspace.invitation.create",
            &actor.email,
            Some(&invitation.id),
        );
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((invitation, receipt))
    }

    /// Atomically replace one pending invitation token and its queued body.
    pub fn resend_workspace_invitation(
        &self,
        workspace_id: &str,
        invitation_id: &str,
        token_hash: &str,
        email_body: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(WorkspaceInvitation, Receipt)> {
        let now = Utc::now();
        let updated_at = now.to_rfc3339();
        let expires_at = (now + Duration::days(WORKSPACE_INVITATION_TTL_DAYS)).to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_workspace_authorized(
            &tx,
            workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Manage,
        )?;
        prune_workspace_invitation_history(&tx, workspace_id)?;
        let changed = tx.execute(
            "UPDATE workspace_invitations SET token_hash = ?1, expires_at = ?2, updated_at = ?3
             WHERE id = ?4 AND workspace_id = ?5 AND status = 'pending'
               AND publication_pending = 0",
            params![
                token_hash,
                &expires_at,
                &updated_at,
                invitation_id,
                workspace_id
            ],
        )?;
        if changed != 1 {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM workspace_invitations
                 WHERE id = ?1 AND workspace_id = ?2)",
                params![invitation_id, workspace_id],
                |row| row.get(0),
            )?;
            return Err(if exists {
                ApiError::Validation("only pending invitations can be resent".to_string())
            } else {
                ApiError::NotFound
            });
        }
        let invitation = tx.query_row(
            "SELECT id, workspace_id, email, role, status, invited_by,
                    expires_at, accepted_at, canceled_at, created_at, updated_at,
                    member_expires_in_seconds
             FROM workspace_invitations WHERE id = ?1 AND workspace_id = ?2",
            params![invitation_id, workspace_id],
            row_to_workspace_invitation,
        )?;
        email_outbox::purge_related_delivery_rows_locked(
            &tx,
            "workspace_invitation",
            invitation_id,
        )?;
        queue_invitation_delivery(&tx, workspace_id, &invitation, email_body)?;
        let receipt = new_receipt(
            "workspace.invitation.resend",
            &actor.email,
            Some(invitation_id),
        );
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((invitation, receipt))
    }

    /// Insert the best-effort UI notice only while the exact invitation token
    /// and role returned by the preceding atomic mutation are still current.
    /// A concurrent replacement/cancel either wins before this transaction or
    /// purges this notice afterwards, so stale notices cannot survive.
    pub fn create_workspace_invitation_notification_if_current(
        &self,
        invitation: &WorkspaceInvitation,
        expected_token_hash: &str,
        title: &str,
        body: &str,
    ) -> ApiResult<bool> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = Utc::now().to_rfc3339();
        let current = tx
            .query_row(
                "SELECT 1 FROM workspace_invitations
                 WHERE id = ?1 AND workspace_id = ?2 AND email = ?3 AND role = ?4
                   AND token_hash = ?5 AND status = 'pending' AND publication_pending = 0
                   AND julianday(expires_at) > julianday(?6)",
                params![
                    &invitation.id,
                    &invitation.workspace_id,
                    &invitation.email,
                    &invitation.role,
                    expected_token_hash,
                    &now,
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !current {
            tx.commit()?;
            return Ok(false);
        }
        let notification = build_notification(
            &invitation.email,
            "workspace_invitation",
            title,
            body,
            Some(&invitation.workspace_id),
            None,
            Some("workspace_invitation"),
            Some(&invitation.id),
        )?;
        ensure_workspace_auxiliary_storage_delta_fits_in_tx(
            &tx,
            &invitation.workspace_id,
            project_notification_storage(&notification.title, &notification.body)?,
        )?;
        insert_notification_locked(&tx, notification)?;
        tx.commit()?;
        Ok(true)
    }
}

fn queue_invitation_delivery(
    tx: &rusqlite::Transaction<'_>,
    workspace_id: &str,
    invitation: &WorkspaceInvitation,
    email_body: &str,
) -> ApiResult<()> {
    insert_workspace_email_outbox_locked(
        tx,
        workspace_id,
        "workspace_invitation",
        &invitation.email,
        "ShellX Drive workspace invitation",
        email_body,
        Some("workspace_invitation"),
        Some(&invitation.id),
    )?;
    Ok(())
}

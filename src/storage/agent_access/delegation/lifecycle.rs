use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::{
    auth::{Actor, DriveCredential, ADMIN_ACTOR},
    error::{ApiError, ApiResult},
    model::DelegatedAgent,
    storage::{authorization, insert_receipt_rows, new_receipt, Storage},
};

use super::{
    super::sso_parent::SsoParentSession, DelegatedAgentPublicationCompletion,
    PendingDelegatedAgentPublication,
};

impl Storage {
    pub(crate) fn get_delegated_agent_for_owner(
        &self,
        principal_id: &str,
        owner_email: &str,
        owner_authority_kind: &str,
    ) -> ApiResult<Option<DelegatedAgent>> {
        let conn = self.conn.lock().unwrap();
        let parent_kind = conn
            .query_row(
                "SELECT delegation_parent_kind FROM agent_principals
                 WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3",
                params![principal_id, owner_email, owner_authority_kind],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(parent_kind) = parent_kind else {
            return Ok(None);
        };
        let owner_is_admin = if parent_kind == "local" {
            delegated_owner_is_admin_locked(&conn, owner_email, owner_authority_kind)?
                .unwrap_or(false)
        } else {
            false
        };
        Ok(conn
            .query_row(
                "SELECT p.id, p.name, p.created_by, p.creator_authority_kind, t.id,
                        t.expires_at, t.last_used_at, t.revoked_at, p.disabled_at, p.created_at
                 FROM agent_principals p
                 JOIN agent_tokens t ON t.id = (
                     SELECT current_token.id FROM agent_tokens current_token
                     WHERE current_token.principal_id = p.id
                       AND current_token.delegation_kind = 'delegated'
                       AND current_token.publication_pending = 0
                     ORDER BY current_token.created_at DESC, current_token.id DESC LIMIT 1
                 )
                 WHERE p.id = ?1 AND p.created_by = ?2 AND p.creator_authority_kind = ?3
                   AND p.publication_pending = 0",
                params![principal_id, owner_email, owner_authority_kind],
                |row| row_to_delegated_agent(row, owner_is_admin),
            )
            .optional()?)
    }

    pub(crate) fn get_current_delegated_agent_for_owner(
        &self,
        principal_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<DelegatedAgent> {
        self.get_delegated_agent_for_owner(
            principal_id,
            &actor.email,
            super::super::agent_creator_authority_kind(actor, source_credential),
        )?
        .ok_or(ApiError::NotFound)
    }

    pub(crate) fn ensure_pending_delegated_agent_publication_authorized(
        &self,
        pending: &PendingDelegatedAgentPublication,
        completion: &DelegatedAgentPublicationCompletion,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        if let Some(retirement) = completion.self_retirement.as_ref() {
            if !pending.rotation
                || pending.principal_id != retirement.principal_id
                || pending.self_rotation_source_token_id.as_deref()
                    != Some(retirement.source_token_id.as_str())
            {
                return Err(ApiError::Unauthenticated);
            }
            ensure_self_delegated_lifecycle_completion(
                &tx,
                retirement,
                Some(&pending.token_id),
                false,
                actor,
                source_credential,
            )?;
        } else {
            authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
            let parent =
                super::super::sso_parent::source_sso_parent_session(&tx, actor, source_credential)?;
            if pending.parent_session.as_ref() != parent.as_ref()
                || !super::super::sso_parent::principal_matches_source(
                    &tx,
                    &pending.principal_id,
                    parent.as_ref(),
                )?
            {
                return Err(ApiError::Unauthenticated);
            }
        }
        tx.commit()?;
        Ok(())
    }
}

mod self_completion;

use self_completion::ensure_self_delegated_lifecycle_completion;

pub(super) fn row_to_delegated_agent(
    row: &Row<'_>,
    owner_is_admin: bool,
) -> rusqlite::Result<DelegatedAgent> {
    let token_expires_at: String = row.get(5)?;
    let token_revoked_at: Option<String> = row.get(7)?;
    let principal_disabled_at: Option<String> = row.get(8)?;
    let active = token_revoked_at.is_none()
        && principal_disabled_at.is_none()
        && !super::super::is_expired(&token_expires_at);
    Ok(DelegatedAgent {
        principal_id: row.get(0)?,
        name: row.get(1)?,
        owner_email: row.get(2)?,
        owner_is_admin,
        token_id: row.get(4)?,
        token_expires_at,
        token_last_used_at: row.get(6)?,
        token_revoked_at,
        principal_disabled: principal_disabled_at.is_some(),
        created_at: row.get(9)?,
        active,
    })
}

/// Only a local account or server operator can currently be an administrator.
pub(super) fn delegated_owner_is_admin_locked(
    conn: &Connection,
    owner_email: &str,
    owner_authority_kind: &str,
) -> ApiResult<Option<bool>> {
    if owner_authority_kind == super::super::AGENT_CREATOR_KIND_OPERATOR {
        return Ok((owner_email == ADMIN_ACTOR).then_some(true));
    }
    Ok(conn
        .query_row(
            "SELECT is_admin FROM auth_accounts
             WHERE email = ?1 AND disabled_at IS NULL",
            params![owner_email],
            |row| Ok(row.get::<_, i64>(0)? != 0),
        )
        .optional()?)
}

pub(super) fn is_expired_at_epoch(value: &str, now_epoch: i64) -> bool {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.timestamp() <= now_epoch)
        .unwrap_or(true)
}

pub(super) fn ensure_delegation_owner_active(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    authority_kind: &str,
    parent: Option<&SsoParentSession>,
) -> ApiResult<()> {
    if parent.is_some() || authority_kind != super::super::AGENT_CREATOR_KIND_USER {
        return Ok(());
    }
    let active = tx
        .query_row(
            "SELECT 1 FROM auth_accounts WHERE email = ?1 AND disabled_at IS NULL",
            params![email],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if active {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

pub(super) fn cancel_pending_delegated_agent(
    tx: &rusqlite::Transaction<'_>,
    pending: &PendingDelegatedAgentPublication,
    actor: &str,
) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    if !pending.rotation {
        tx.execute(
            "UPDATE agent_principals SET disabled_at = COALESCE(disabled_at, ?2),
                    publication_pending = 0 WHERE id = ?1 AND publication_pending = 1",
            params![&pending.principal_id, &now],
        )?;
    }
    tx.execute(
        "UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, ?2), publication_pending = 0
         WHERE id = ?1 AND principal_id = ?3 AND publication_pending = 1",
        params![&pending.token_id, &now, &pending.principal_id],
    )?;
    let receipt = new_receipt(
        "agent_delegation.revoke.stale_publication",
        actor,
        Some(&pending.principal_id),
    );
    insert_receipt_rows(tx, &receipt)?;
    Ok(())
}

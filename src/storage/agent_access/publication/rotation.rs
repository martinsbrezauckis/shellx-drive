use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    storage::{authorization, insert_receipt_rows, new_receipt, Storage},
};

use super::super::{agent_creator_authority_kind, ACTIVE_GRANT_CREATOR_PREDICATE};
use super::PendingAgentPrincipalRotation;

impl Storage {
    pub(crate) fn stage_pending_agent_principal_rotation(
        &self,
        principal_id: &str,
        token_digest: &str,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<PendingAgentPrincipalRotation> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let token_id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
            let principal_exists = tx
                .query_row(
                    "SELECT 1 FROM agent_principals
                     WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                       AND publication_pending = 0 AND disabled_at IS NULL",
                    params![principal_id, &actor.email, creator_authority_kind],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !principal_exists {
                return Err(ApiError::Forbidden);
            }
            let workspace_ids = {
                let sql = format!(
                    "SELECT DISTINCT g.workspace_id
                     FROM agent_folder_grants g
                     JOIN agent_principals p ON p.id = g.principal_id
                     WHERE g.principal_id = ?1 AND g.publication_pending = 0
                       AND g.revoked_at IS NULL
                       AND datetime(g.expires_at) > datetime(?2)
                       AND {ACTIVE_GRANT_CREATOR_PREDICATE}
                     ORDER BY g.workspace_id ASC"
                );
                let mut statement = tx.prepare(&sql)?;
                let workspaces = statement
                    .query_map(params![principal_id, &now], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                workspaces
            };
            if workspace_ids.is_empty() {
                return Err(ApiError::Validation(
                    "AI agents need an active folder grant before rotating keys".to_string(),
                ));
            }
            for workspace_id in &workspace_ids {
                authorization::ensure_workspace_authorized(
                    &tx,
                    workspace_id,
                    actor,
                    source_credential,
                    WorkspacePermission::Write,
                )?;
            }
            super::limits::ensure_token_capacity(&tx, principal_id)?;
            tx.execute(
                "INSERT INTO agent_tokens (
                    id, principal_id, token_hash, expires_at, last_used_at,
                    revoked_at, created_at, publication_pending
                 ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5, 1)",
                params![&token_id, principal_id, token_digest, expires_at, &now],
            )?;
            tx.commit()?;
        }
        Ok(PendingAgentPrincipalRotation {
            receipt: new_receipt("agent_principal.rotate", &actor.email, Some(principal_id)),
            principal_id: principal_id.to_string(),
            token_id,
        })
    }

    /// Publish a staged rotation only at the same linearization point that
    /// retires the former live token. A denied publication only revokes the
    /// staged token, leaving the old token exactly as it was.
    pub(crate) fn publish_pending_agent_principal_rotation(
        &self,
        pending: &PendingAgentPrincipalRotation,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revalidated = (|| {
            let now = Utc::now().to_rfc3339();
            let current_workspace_ids = {
                let sql = format!(
                    "SELECT DISTINCT g.workspace_id
                     FROM agent_folder_grants g
                     JOIN agent_principals p ON p.id = g.principal_id
                     WHERE g.principal_id = ?1 AND g.publication_pending = 0
                       AND g.revoked_at IS NULL
                       AND datetime(g.expires_at) > datetime(?2)
                       AND {ACTIVE_GRANT_CREATOR_PREDICATE}
                     ORDER BY g.workspace_id ASC"
                );
                let mut statement = tx.prepare(&sql)?;
                let workspace_ids = statement
                    .query_map(params![&pending.principal_id, &now], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                workspace_ids
            };
            if current_workspace_ids.is_empty() {
                return Err(ApiError::Validation(
                    "AI agents need an active folder grant before rotating keys".to_string(),
                ));
            }
            for workspace_id in &current_workspace_ids {
                authorization::ensure_workspace_authorized(
                    &tx,
                    workspace_id,
                    actor,
                    source_credential,
                    WorkspacePermission::Write,
                )?;
            }
            let principal_is_current = tx
                .query_row(
                    "SELECT 1 FROM agent_principals
                     WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                       AND publication_pending = 0 AND disabled_at IS NULL",
                    params![&pending.principal_id, &actor.email, creator_authority_kind],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if principal_is_current {
                Ok(())
            } else {
                Err(ApiError::Forbidden)
            }
        })();
        match revalidated {
            Ok(()) => {
                let published = tx.execute(
                    "UPDATE agent_tokens SET publication_pending = 0
                     WHERE id = ?1 AND principal_id = ?2
                       AND publication_pending = 1 AND revoked_at IS NULL",
                    params![&pending.token_id, &pending.principal_id],
                )?;
                if published != 1 {
                    return Err(ApiError::Conflict);
                }
                let retired = tx.execute(
                    "UPDATE agent_tokens SET revoked_at = ?3
                     WHERE principal_id = ?1 AND id != ?2
                       AND publication_pending = 0 AND revoked_at IS NULL",
                    params![
                        &pending.principal_id,
                        &pending.token_id,
                        Utc::now().to_rfc3339()
                    ],
                )?;
                if retired == 0 {
                    return Err(ApiError::Conflict);
                }
                insert_receipt_rows(&tx, &pending.receipt)?;
                tx.commit()?;
                Ok(())
            }
            Err(error) => {
                cancel_pending_agent_rotation_in_tx(&tx, pending, &actor.email)?;
                tx.commit()?;
                Err(error)
            }
        }
    }
}

fn cancel_pending_agent_rotation_in_tx(
    tx: &rusqlite::Transaction<'_>,
    pending: &PendingAgentPrincipalRotation,
    actor: &str,
) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    let canceled = tx.execute(
        "UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, ?2)
         WHERE id = ?1 AND principal_id = ?3 AND publication_pending = 1",
        params![&pending.token_id, &now, &pending.principal_id],
    )?;
    if canceled != 1 {
        return Err(ApiError::Conflict);
    }
    let receipt = new_receipt(
        "agent_principal.rotate.stale_publication",
        actor,
        Some(&pending.principal_id),
    );
    insert_receipt_rows(tx, &receipt)?;
    Ok(())
}

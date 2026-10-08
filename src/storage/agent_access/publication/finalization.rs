use chrono::Utc;
use rusqlite::{params, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{AgentAccess, AgentPrincipal, FileKind},
    storage::{authorization, insert_receipt_rows, new_receipt, Storage},
};

use super::super::{
    active_grant_locked, agent_creator_authority_kind, agent_token_active_locked,
    query_agent_principal_page_locked, query_file_locked, DEFAULT_AGENT_PRINCIPAL_PAGE_LIMIT,
};
use super::{PendingAgentAccessPublication, PendingAgentAccessPublicationKind};

impl Storage {
    /// Publish a newly minted agent bearer or grant only if the exact human
    /// credential and its original workspace Write authority remain current.
    pub(crate) fn publish_pending_agent_access(
        &self,
        pending: &PendingAgentAccessPublication,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let workspace_id = match &pending.kind {
            PendingAgentAccessPublicationKind::NewPrincipal { workspace_id, .. }
            | PendingAgentAccessPublicationKind::Grant { workspace_id, .. } => workspace_id,
        };
        let result = (|| {
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            ensure_pending_agent_access_subject_active_in_tx(&tx, pending)?;
            publish_pending_agent_access_in_tx(&tx, pending, actor, source_credential)?;
            insert_receipt_rows(&tx, &pending.receipt)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                tx.commit()?;
                Ok(())
            }
            Err(error) => {
                cancel_pending_agent_access_in_tx(&tx, pending, &actor.email)?;
                tx.commit()?;
                Err(error)
            }
        }
    }

    pub(crate) fn get_current_agent_principal_for_creator(
        &self,
        principal_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<AgentPrincipal> {
        let conn = self.conn.lock().unwrap();
        query_agent_principal_page_locked(
            &conn,
            principal_id,
            &actor.email,
            agent_creator_authority_kind(actor, source_credential),
            DEFAULT_AGENT_PRINCIPAL_PAGE_LIMIT,
        )?
        .ok_or(ApiError::NotFound)
    }

    /// Revalidate the exact credential and every grant selected for the
    /// `/agent/v1/access` response immediately before its JSON leaves Drive.
    pub(crate) fn ensure_agent_session_publication_authorized(
        &self,
        principal_id: &str,
        token_id: &str,
        selected_grants: &[AgentAccess],
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        if !agent_token_active_locked(&tx, principal_id, token_id)? {
            return Err(ApiError::Forbidden);
        }
        for selected in selected_grants {
            let current =
                active_grant_locked(&tx, principal_id, token_id, &selected.grant_id, false)?;
            if !same_agent_session_subject(selected, &current) {
                return Err(ApiError::Forbidden);
            }
        }
        tx.commit()?;
        Ok(())
    }
}

fn ensure_pending_agent_access_subject_active_in_tx(
    tx: &rusqlite::Transaction<'_>,
    pending: &PendingAgentAccessPublication,
) -> ApiResult<()> {
    let root = query_file_locked(tx, &pending.access.root_file_id)?.ok_or(ApiError::NotFound)?;
    if root.workspace_id != pending.access.workspace_id
        || super::super::file_is_effectively_trashed_locked(tx, &pending.access.root_file_id)?
        || !matches!(root.kind, FileKind::Folder)
    {
        return Err(ApiError::Validation(
            "AI access requires an active folder".to_string(),
        ));
    }
    if matches!(
        &pending.kind,
        PendingAgentAccessPublicationKind::Grant { .. }
    ) && !agent_token_active_locked(tx, &pending.access.principal_id, &pending.access.token_id)?
    {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn publish_pending_agent_access_in_tx(
    tx: &rusqlite::Transaction<'_>,
    pending: &PendingAgentAccessPublication,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
    match &pending.kind {
        PendingAgentAccessPublicationKind::NewPrincipal {
            principal_id,
            token_id,
            grant_id,
            workspace_id,
        } => {
            let principal_published = tx.execute(
                "UPDATE agent_principals SET publication_pending = 0
                 WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                   AND publication_pending = 1 AND disabled_at IS NULL",
                params![principal_id, &actor.email, creator_authority_kind],
            )?;
            let token_published = tx.execute(
                "UPDATE agent_tokens SET publication_pending = 0
                 WHERE id = ?1 AND principal_id = ?2
                   AND publication_pending = 1 AND revoked_at IS NULL",
                params![token_id, principal_id],
            )?;
            let grant_published = tx.execute(
                "UPDATE agent_folder_grants SET publication_pending = 0
                 WHERE id = ?1 AND principal_id = ?2 AND workspace_id = ?3
                   AND publication_pending = 1 AND revoked_at IS NULL",
                params![grant_id, principal_id, workspace_id],
            )?;
            if principal_published != 1 || token_published != 1 || grant_published != 1 {
                return Err(ApiError::Conflict);
            }
        }
        PendingAgentAccessPublicationKind::Grant {
            principal_id,
            grant_id,
            workspace_id,
        } => {
            let grant_published = tx.execute(
                "UPDATE agent_folder_grants SET publication_pending = 0,
                    revoked_at = NULL
                 WHERE id = ?1 AND principal_id = ?2 AND workspace_id = ?3
                   AND publication_pending = 1",
                params![grant_id, principal_id, workspace_id],
            )?;
            if grant_published != 1 {
                return Err(ApiError::Conflict);
            }
            tx.execute(
                "UPDATE agent_folder_grants
                 SET revoked_at = COALESCE(revoked_at, ?4)
                 WHERE principal_id = ?1 AND root_file_id = ?2 AND id != ?3
                   AND publication_pending = 0 AND revoked_at IS NULL",
                params![
                    principal_id,
                    &pending.access.root_file_id,
                    grant_id,
                    Utc::now().to_rfc3339()
                ],
            )?;
        }
    }
    Ok(())
}

fn cancel_pending_agent_access_in_tx(
    tx: &rusqlite::Transaction<'_>,
    pending: &PendingAgentAccessPublication,
    actor: &str,
) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    let target_id = match &pending.kind {
        PendingAgentAccessPublicationKind::NewPrincipal {
            principal_id,
            token_id,
            grant_id,
            ..
        } => {
            tx.execute(
                "UPDATE agent_principals SET disabled_at = COALESCE(disabled_at, ?2)
                 WHERE id = ?1 AND publication_pending = 1",
                params![principal_id, &now],
            )?;
            tx.execute(
                "UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, ?2)
                 WHERE id = ?1 AND principal_id = ?3 AND publication_pending = 1",
                params![token_id, &now, principal_id],
            )?;
            tx.execute(
                "UPDATE agent_folder_grants SET revoked_at = COALESCE(revoked_at, ?2)
                 WHERE id = ?1 AND principal_id = ?3 AND publication_pending = 1",
                params![grant_id, &now, principal_id],
            )?;
            grant_id
        }
        PendingAgentAccessPublicationKind::Grant {
            principal_id,
            grant_id,
            ..
        } => {
            tx.execute(
                "UPDATE agent_folder_grants SET revoked_at = COALESCE(revoked_at, ?2)
                 WHERE id = ?1 AND principal_id = ?3 AND publication_pending = 1",
                params![grant_id, &now, principal_id],
            )?;
            grant_id
        }
    };
    let receipt = new_receipt(
        "agent_access.revoke.stale_publication",
        actor,
        Some(target_id),
    );
    insert_receipt_rows(tx, &receipt)?;
    Ok(())
}

fn same_agent_session_subject(selected: &AgentAccess, current: &AgentAccess) -> bool {
    selected.principal_id == current.principal_id
        && selected.grant_id == current.grant_id
        && selected.token_id == current.token_id
        && selected.workspace_id == current.workspace_id
        && selected.root_file_id == current.root_file_id
        && selected.permission == current.permission
        && selected.expires_at == current.expires_at
        && selected.created_by == current.created_by
        && selected.created_at == current.created_at
}

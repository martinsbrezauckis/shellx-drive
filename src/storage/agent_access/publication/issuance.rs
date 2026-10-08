use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{AgentPermission, FileKind},
    storage::{authorization, new_receipt, Storage},
};

use super::super::{
    agent_creator_authority_kind, agent_token_active_locked, file_is_effectively_trashed_locked,
    query_file_locked,
};
use super::{PendingAgentAccessPublication, PendingAgentAccessPublicationKind};

impl Storage {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_pending_agent_access_publication(
        &self,
        name: &str,
        workspace_id: &str,
        root_file_id: &str,
        permission: AgentPermission,
        token_digest: &str,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<PendingAgentAccessPublication> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let principal_id = Uuid::now_v7().to_string();
        let token_id = Uuid::now_v7().to_string();
        let grant_id = Uuid::now_v7().to_string();
        let created_at = Utc::now().to_rfc3339();
        let receipt = new_receipt("agent_access.create", &actor.email, Some(&grant_id));
        let (root_name, workspace_name) = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            let root = query_file_locked(&tx, root_file_id)?.ok_or(ApiError::NotFound)?;
            if root.workspace_id != workspace_id
                || file_is_effectively_trashed_locked(&tx, root_file_id)?
                || !matches!(root.kind, FileKind::Folder)
            {
                return Err(ApiError::Validation(
                    "AI access requires an active folder".to_string(),
                ));
            }
            let duplicate_name = tx
                .query_row(
                    "SELECT 1 FROM agent_principals
                     WHERE created_by = ?1 AND creator_authority_kind = ?2
                       AND name = ?3 COLLATE NOCASE AND disabled_at IS NULL
                     LIMIT 1",
                    params![&actor.email, creator_authority_kind, name],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if duplicate_name {
                return Err(ApiError::Validation(
                    "an AI agent with this name already exists; select it instead".to_string(),
                ));
            }
            super::limits::ensure_principal_capacity(&tx, &actor.email)?;
            let workspace_name = tx.query_row(
                "SELECT name FROM workspaces WHERE id = ?1",
                params![workspace_id],
                |row| row.get::<_, String>(0),
            )?;
            tx.execute(
                "INSERT INTO agent_principals (
                    id, name, created_by, creator_authority_kind, disabled_at,
                    created_at, publication_pending
                 ) VALUES (?1, ?2, ?3, ?4, NULL, ?5, 1)",
                params![
                    &principal_id,
                    name,
                    &actor.email,
                    creator_authority_kind,
                    &created_at,
                ],
            )?;
            tx.execute(
                "INSERT INTO agent_tokens (
                    id, principal_id, token_hash, expires_at, last_used_at,
                    revoked_at, created_at, publication_pending
                 ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5, 1)",
                params![
                    &token_id,
                    &principal_id,
                    token_digest,
                    expires_at,
                    &created_at
                ],
            )?;
            tx.execute(
                "INSERT INTO agent_folder_grants (
                    id, principal_id, workspace_id, root_file_id, permission,
                    expires_at, revoked_at, created_by, creator_authority_kind,
                    created_at, publication_pending
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, 1)",
                params![
                    &grant_id,
                    &principal_id,
                    workspace_id,
                    root_file_id,
                    permission.as_db_str(),
                    expires_at,
                    &actor.email,
                    creator_authority_kind,
                    &created_at,
                ],
            )?;
            tx.commit()?;
            (root.name, workspace_name)
        };
        Ok(PendingAgentAccessPublication {
            access: pending_access(
                &principal_id,
                name,
                &grant_id,
                workspace_id,
                root_file_id,
                permission,
                expires_at,
                &token_id,
                expires_at,
                None,
                None,
                &actor.email,
                &created_at,
                &root_name,
                &workspace_name,
            ),
            receipt,
            kind: PendingAgentAccessPublicationKind::NewPrincipal {
                principal_id,
                token_id,
                grant_id,
                workspace_id: workspace_id.to_string(),
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn grant_pending_agent_access_publication(
        &self,
        principal_id: &str,
        workspace_id: &str,
        root_file_id: &str,
        permission: AgentPermission,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<PendingAgentAccessPublication> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let now = Utc::now().to_rfc3339();
        let (access, grant_id) = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_workspace_authorized(
                &tx,
                workspace_id,
                actor,
                source_credential,
                WorkspacePermission::Write,
            )?;
            let principal_name = tx
                .query_row(
                    "SELECT name FROM agent_principals
                     WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                       AND publication_pending = 0 AND disabled_at IS NULL",
                    params![principal_id, &actor.email, creator_authority_kind],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::Forbidden)?;
            let (token_id, token_expires_at, token_last_used_at, token_revoked_at) = tx
                .query_row(
                    "SELECT id, expires_at, last_used_at, revoked_at
                     FROM agent_tokens
                     WHERE principal_id = ?1 AND publication_pending = 0
                       AND revoked_at IS NULL
                     ORDER BY created_at DESC, id DESC LIMIT 1",
                    params![principal_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    ApiError::Validation("rotate this AI agent's key before sharing".to_string())
                })?;
            if !agent_token_active_locked(&tx, principal_id, &token_id)? {
                return Err(ApiError::Validation(
                    "rotate this AI agent's key before sharing".to_string(),
                ));
            }
            let root = query_file_locked(&tx, root_file_id)?.ok_or(ApiError::NotFound)?;
            if root.workspace_id != workspace_id
                || file_is_effectively_trashed_locked(&tx, root_file_id)?
                || !matches!(root.kind, FileKind::Folder)
            {
                return Err(ApiError::Validation(
                    "AI access requires an active folder".to_string(),
                ));
            }
            let workspace_name = tx.query_row(
                "SELECT name FROM workspaces WHERE id = ?1",
                params![workspace_id],
                |row| row.get::<_, String>(0),
            )?;
            let revoked_grant_id = tx
                .query_row(
                    "SELECT id FROM agent_folder_grants g
                     WHERE principal_id = ?1 AND root_file_id = ?2
                       AND publication_pending = 0 AND revoked_at IS NOT NULL
                       AND NOT EXISTS (SELECT 1 FROM office_edit_sessions s WHERE s.source_credential_id = g.id)
                       AND NOT EXISTS (SELECT 1 FROM backup_jobs b WHERE b.source_credential_id = g.id)
                     ORDER BY created_at DESC, id DESC LIMIT 1",
                    params![principal_id, root_file_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let grant_id = revoked_grant_id.unwrap_or_else(|| Uuid::now_v7().to_string());
            super::limits::ensure_grant_capacity(&tx, principal_id, &grant_id)?;
            tx.execute(
                "INSERT INTO agent_folder_grants (
                    id, principal_id, workspace_id, root_file_id, permission,
                    expires_at, revoked_at, created_by, creator_authority_kind,
                    created_at, publication_pending
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, 1)
                 ON CONFLICT(id) DO UPDATE SET
                    principal_id = excluded.principal_id,
                    workspace_id = excluded.workspace_id,
                    root_file_id = excluded.root_file_id,
                    permission = excluded.permission,
                    expires_at = excluded.expires_at,
                    created_by = excluded.created_by,
                    creator_authority_kind = excluded.creator_authority_kind,
                    created_at = excluded.created_at,
                    publication_pending = 1",
                params![
                    &grant_id,
                    principal_id,
                    workspace_id,
                    root_file_id,
                    permission.as_db_str(),
                    expires_at,
                    &actor.email,
                    creator_authority_kind,
                    &now,
                ],
            )?;
            tx.commit()?;
            (
                pending_access(
                    principal_id,
                    &principal_name,
                    &grant_id,
                    workspace_id,
                    root_file_id,
                    permission,
                    expires_at,
                    &token_id,
                    &token_expires_at,
                    token_last_used_at,
                    token_revoked_at,
                    &actor.email,
                    &now,
                    &root.name,
                    &workspace_name,
                ),
                grant_id,
            )
        };
        let receipt = new_receipt("agent_access.grant", &actor.email, Some(&grant_id));
        Ok(PendingAgentAccessPublication {
            access,
            receipt,
            kind: PendingAgentAccessPublicationKind::Grant {
                principal_id: principal_id.to_string(),
                grant_id,
                workspace_id: workspace_id.to_string(),
            },
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn pending_access(
    principal_id: &str,
    name: &str,
    grant_id: &str,
    workspace_id: &str,
    root_file_id: &str,
    permission: AgentPermission,
    expires_at: &str,
    token_id: &str,
    token_expires_at: &str,
    token_last_used_at: Option<String>,
    token_revoked_at: Option<String>,
    created_by: &str,
    created_at: &str,
    root_name: &str,
    workspace_name: &str,
) -> crate::model::AgentAccess {
    crate::model::AgentAccess {
        principal_id: principal_id.to_string(),
        name: name.to_string(),
        grant_id: grant_id.to_string(),
        workspace_id: workspace_id.to_string(),
        root_file_id: root_file_id.to_string(),
        permission,
        expires_at: expires_at.to_string(),
        grant_revoked_at: None,
        token_id: token_id.to_string(),
        token_expires_at: token_expires_at.to_string(),
        token_last_used_at,
        token_revoked_at,
        principal_disabled: false,
        created_by: created_by.to_string(),
        created_at: created_at.to_string(),
        root_name: root_name.to_string(),
        workspace_name: workspace_name.to_string(),
        active: true,
    }
}

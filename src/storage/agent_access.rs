use std::collections::HashSet;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, AuthMode, DriveCredential, ADMIN_ACTOR},
    error::{ApiError, ApiResult},
    model::{AgentAccess, AgentPermission, AgentPrincipal, DriveFile, FileKind, Receipt},
};

use super::{
    authorization::{
        ensure_agent_creator_authorized, ensure_source_credential_active,
        ensure_workspace_authorized,
    },
    bounded_files::{ensure_workspace_node_capacity, file_is_effectively_trashed_locked},
    enforce_quota_in_txn, insert_receipt_rows, new_receipt, record_sync_change_for_receipt,
    refresh_file_search_index_locked, row_to_file, validate_file_name, Storage,
    MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES,
};

mod delegation;
mod file_mutations;
mod publication;
mod sso_parent;

pub(crate) use sso_parent::delegated_sso_parent_is_active;

const FILE_COLUMNS: &str = "id, workspace_id, parent_id, name, kind, revision, trashed, starred, \
     content_hash, created_at, updated_at, content_bytes, cover_hash";
const QUALIFIED_FILE_COLUMNS: &str =
    "files.id, files.workspace_id, files.parent_id, files.name, files.kind, \
     files.revision, files.trashed, files.starred, files.content_hash, \
     files.created_at, files.updated_at, files.content_bytes, files.cover_hash";

pub(super) const ACCESS_SELECT: &str =
    "SELECT p.id, p.name, g.id, g.workspace_id, g.root_file_id, g.permission, \
            g.expires_at, g.revoked_at, t.id, t.expires_at, t.last_used_at, \
            t.revoked_at, g.created_by, g.created_at, p.disabled_at, \
            root.name, workspace.name \
     FROM agent_folder_grants g \
     JOIN agent_principals p ON p.id = g.principal_id \
     JOIN files root ON root.id = g.root_file_id \
     JOIN workspaces workspace ON workspace.id = g.workspace_id \
     JOIN agent_tokens t ON t.id = ( \
         SELECT current_token.id FROM agent_tokens current_token \
         WHERE current_token.principal_id = p.id \
           AND current_token.delegation_kind = 'folder' \
           AND current_token.publication_pending = 0 \
         ORDER BY current_token.created_at DESC, current_token.id DESC LIMIT 1 \
     )";

// Human management views intentionally show the current token metadata. Agent
// routes must instead bind authorization to the exact token that authenticated
// the request, so a rotation or revocation cannot be replaced by a newer token
// for the same principal between request authentication and authorization.
const AGENT_ACCESS_SELECT: &str =
    "SELECT p.id, p.name, g.id, g.workspace_id, g.root_file_id, g.permission, \
            g.expires_at, g.revoked_at, t.id, t.expires_at, t.last_used_at, \
            t.revoked_at, g.created_by, g.created_at, p.disabled_at, \
            root.name, workspace.name \
     FROM agent_folder_grants g \
     JOIN agent_principals p ON p.id = g.principal_id \
     JOIN files root ON root.id = g.root_file_id \
     JOIN workspaces workspace ON workspace.id = g.workspace_id \
     JOIN agent_tokens t ON t.id = ?1 AND t.principal_id = p.id \
        AND t.delegation_kind = 'folder' \
        AND t.publication_pending = 0";

const AGENT_CREATOR_KIND_USER: &str = "user";
const AGENT_CREATOR_KIND_OPERATOR: &str = "operator";

// Agent grants are delegated authority, not ownership detached from its
// creator. A grant is server managed only when its persisted provenance proves
// it came from the un-downshifted internal operator. The operator's display
// email is not itself authority: legacy rows using that string but lacking the
// provenance marker fail closed.
pub(super) const ACTIVE_GRANT_CREATOR_PREDICATE: &str = "(
      p.created_by = g.created_by
      AND p.creator_authority_kind = g.creator_authority_kind
      AND (
        (p.creator_authority_kind = 'operator'
          AND g.creator_authority_kind = 'operator'
          AND g.created_by = 'system@local')
        OR (
          p.creator_authority_kind = 'user'
          AND g.creator_authority_kind = 'user'
          AND (
        NOT EXISTS (
          SELECT 1 FROM auth_accounts disabled_creator
          WHERE disabled_creator.email = g.created_by
            AND disabled_creator.disabled_at IS NOT NULL
        )
        AND (
          EXISTS (
            SELECT 1 FROM auth_accounts aa
            WHERE aa.email = g.created_by AND aa.is_admin = 1 AND aa.disabled_at IS NULL
          )
          OR EXISTS (
            SELECT 1 FROM workspace_members wm
            JOIN users creator ON creator.id = wm.user_id
            WHERE wm.workspace_id = g.workspace_id AND creator.email = g.created_by
              AND wm.role IN ('owner', 'editor')
              AND (wm.expires_at IS NULL OR julianday(wm.expires_at) > julianday('now'))
          )
          OR EXISTS (
            SELECT 1 FROM workspace_group_grants wgg
            JOIN group_members gm ON gm.group_id = wgg.group_id
            JOIN users creator ON creator.id = gm.user_id
            WHERE wgg.workspace_id = g.workspace_id AND creator.email = g.created_by
              AND wgg.role IN ('owner', 'editor')
          )
        )
          )
        )
      )
    )";

const DEFAULT_AGENT_PRINCIPAL_PAGE_LIMIT: usize = 25;
pub const MAX_AGENT_PRINCIPAL_PAGE_LIMIT: usize = 50;

#[derive(Debug, Clone)]
pub struct AuthenticatedAgentToken {
    pub principal_id: String,
    pub principal_name: String,
    pub token_id: String,
}

/// Authentication result for an account-wide delegation. It intentionally has
/// a different type from [`AuthenticatedAgentToken`], whose bearer remains
/// limited to the legacy `/agent/v1` folder-grant routes.
#[derive(Debug, Clone)]
pub struct AuthenticatedDelegatedAgentToken {
    pub principal_id: String,
    pub owner_email: String,
    pub owner_is_admin: bool,
    pub token_id: String,
}

#[derive(Debug, Default)]
pub struct AgentFileUpdate {
    pub base_revision: Option<i64>,
    pub name: Option<String>,
    pub parent_id: Option<String>,
    pub collision_policy: Option<String>,
    pub replace_target_id: Option<String>,
    pub replace_target_revision: Option<i64>,
}

impl Storage {
    #[allow(clippy::too_many_arguments)]
    pub fn create_agent_access(
        &self,
        name: &str,
        workspace_id: &str,
        root_file_id: &str,
        permission: AgentPermission,
        token_digest: &str,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AgentAccess, Receipt)> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let principal_id = Uuid::now_v7().to_string();
        let token_id = Uuid::now_v7().to_string();
        let grant_id = Uuid::now_v7().to_string();
        let created_at = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_agent_creator_authorized(&tx, workspace_id, actor, source_credential)?;
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
                       AND publication_pending = 0
                       AND name = ?3 COLLATE NOCASE AND disabled_at IS NULL LIMIT 1",
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
            tx.execute(
                "INSERT INTO agent_principals (
                    id, name, created_by, creator_authority_kind, disabled_at, created_at
                 ) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                params![
                    principal_id,
                    name,
                    &actor.email,
                    creator_authority_kind,
                    created_at,
                ],
            )?;
            tx.execute(
                "INSERT INTO agent_tokens (
                    id, principal_id, token_hash, expires_at, last_used_at,
                    revoked_at, created_at
                 ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
                params![token_id, principal_id, token_digest, expires_at, created_at],
            )?;
            tx.execute(
                "INSERT INTO agent_folder_grants (
                    id, principal_id, workspace_id, root_file_id, permission,
                    expires_at, revoked_at, created_by, creator_authority_kind, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9)",
                params![
                    grant_id,
                    principal_id,
                    workspace_id,
                    root_file_id,
                    permission.as_db_str(),
                    expires_at,
                    &actor.email,
                    creator_authority_kind,
                    created_at,
                ],
            )?;
            tx.commit()?;
        }
        let access = self
            .get_agent_access(&grant_id)?
            .ok_or(ApiError::NotFound)?;
        let receipt = self.insert_receipt("agent_access.create", &actor.email, Some(&grant_id))?;
        Ok((access, receipt))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn grant_existing_agent_access(
        &self,
        principal_id: &str,
        workspace_id: &str,
        root_file_id: &str,
        permission: AgentPermission,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AgentAccess, Receipt)> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let now = Utc::now().to_rfc3339();
        let grant_id = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_agent_creator_authorized(&tx, workspace_id, actor, source_credential)?;
            let disabled_at = tx
                .query_row(
                    "SELECT disabled_at FROM agent_principals
                     WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                       AND publication_pending = 0
                       AND EXISTS (SELECT 1 FROM agent_tokens t
                                   WHERE t.principal_id = agent_principals.id
                                     AND t.delegation_kind = 'folder')",
                    params![principal_id, &actor.email, creator_authority_kind],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .ok_or(ApiError::Forbidden)?;
            if disabled_at.is_some() {
                return Err(ApiError::Validation(
                    "disabled AI agents cannot receive folder access".to_string(),
                ));
            }
            let current_token_id = tx
                .query_row(
                    "SELECT id FROM agent_tokens WHERE principal_id = ?1
                       AND delegation_kind = 'folder'
                       AND publication_pending = 0
                     ORDER BY created_at DESC, id DESC LIMIT 1",
                    params![principal_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| {
                    ApiError::Validation("rotate this AI agent's key before sharing".to_string())
                })?;
            if !agent_token_active_locked(&tx, principal_id, &current_token_id)? {
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
            let existing = tx
                .query_row(
                    "SELECT id FROM agent_folder_grants
                     WHERE principal_id = ?1 AND root_file_id = ?2
                       AND publication_pending = 0
                     ORDER BY created_at DESC, id DESC LIMIT 1",
                    params![principal_id, root_file_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let grant_id = existing.unwrap_or_else(|| Uuid::now_v7().to_string());
            tx.execute(
                "INSERT INTO agent_folder_grants (
                    id, principal_id, workspace_id, root_file_id, permission,
                    expires_at, revoked_at, created_by, creator_authority_kind, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9)
                 ON CONFLICT(id) DO UPDATE SET
                    workspace_id = excluded.workspace_id,
                    root_file_id = excluded.root_file_id,
                    permission = excluded.permission,
                    expires_at = excluded.expires_at,
                    revoked_at = NULL,
                    created_by = excluded.created_by,
                    creator_authority_kind = excluded.creator_authority_kind,
                    publication_pending = 0,
                    created_at = excluded.created_at",
                params![
                    grant_id,
                    principal_id,
                    workspace_id,
                    root_file_id,
                    permission.as_db_str(),
                    expires_at,
                    &actor.email,
                    creator_authority_kind,
                    now,
                ],
            )?;
            tx.commit()?;
            grant_id
        };
        let access = self
            .get_agent_access(&grant_id)?
            .ok_or(ApiError::NotFound)?;
        let receipt = self.insert_receipt("agent_access.grant", &actor.email, Some(&grant_id))?;
        Ok((access, receipt))
    }

    pub fn list_agent_access_for_root(
        &self,
        root_file_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> ApiResult<(Vec<AgentAccess>, Option<String>)> {
        validate_agent_principal_page_limit(limit)?;
        let conn = self.conn.lock().unwrap();
        let mut access = match cursor {
            Some(cursor) => {
                let sql = format!(
                    "{ACCESS_SELECT} WHERE g.root_file_id = ?1 AND g.id > ?2
                     AND p.publication_pending = 0 AND g.publication_pending = 0
                     AND {ACTIVE_GRANT_CREATOR_PREDICATE}
                     ORDER BY g.id ASC LIMIT ?3"
                );
                let mut statement = conn.prepare(&sql)?;
                let rows = statement.query_map(
                    params![root_file_id, cursor, (limit + 1) as i64],
                    row_to_agent_access,
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let sql = format!(
                    "{ACCESS_SELECT} WHERE g.root_file_id = ?1
                     AND p.publication_pending = 0 AND g.publication_pending = 0
                     AND {ACTIVE_GRANT_CREATOR_PREDICATE} ORDER BY g.id ASC LIMIT ?2"
                );
                let mut statement = conn.prepare(&sql)?;
                let rows = statement.query_map(
                    params![root_file_id, (limit + 1) as i64],
                    row_to_agent_access,
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        let has_more = access.len() > limit;
        access.truncate(limit);
        let next_cursor = has_more
            .then(|| access.last().map(|grant| grant.grant_id.clone()))
            .flatten();
        Ok((access, next_cursor))
    }

    pub fn list_agent_principals_for_creator(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
        cursor: Option<&str>,
        limit: usize,
    ) -> ApiResult<(Vec<AgentPrincipal>, Option<String>)> {
        validate_agent_principal_page_limit(limit)?;
        let created_by = &actor.email;
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let conn = self.conn.lock().unwrap();
        let mut ids = match cursor {
            Some(cursor) => {
                let mut statement = conn.prepare(
                    "SELECT id FROM agent_principals
                     WHERE created_by = ?1 AND creator_authority_kind = ?2
                       AND publication_pending = 0
                       AND disabled_at IS NULL AND id > ?3
                       AND EXISTS (SELECT 1 FROM agent_tokens t
                                   WHERE t.principal_id = agent_principals.id
                                     AND t.delegation_kind = 'folder')
                     ORDER BY id ASC LIMIT ?4",
                )?;
                let rows = statement.query_map(
                    params![
                        created_by,
                        creator_authority_kind,
                        cursor,
                        (limit + 1) as i64
                    ],
                    |row| row.get::<_, String>(0),
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let mut statement = conn.prepare(
                    "SELECT id FROM agent_principals
                     WHERE created_by = ?1 AND creator_authority_kind = ?2
                       AND publication_pending = 0
                       AND disabled_at IS NULL
                       AND EXISTS (SELECT 1 FROM agent_tokens t
                                   WHERE t.principal_id = agent_principals.id
                                     AND t.delegation_kind = 'folder')
                     ORDER BY id ASC LIMIT ?3",
                )?;
                let rows = statement.query_map(
                    params![created_by, creator_authority_kind, (limit + 1) as i64],
                    |row| row.get::<_, String>(0),
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        let has_more = ids.len() > limit;
        ids.truncate(limit);
        let next_cursor = has_more.then(|| ids.last().cloned()).flatten();
        let agents = ids
            .into_iter()
            .map(|principal_id| {
                query_agent_principal_page_locked(
                    &conn,
                    &principal_id,
                    created_by,
                    creator_authority_kind,
                    limit,
                )?
                .ok_or(ApiError::NotFound)
            })
            .collect::<ApiResult<Vec<_>>>()?;
        Ok((agents, next_cursor))
    }

    pub fn list_agent_principal_grants_for_creator(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
        principal_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> ApiResult<(Vec<AgentAccess>, Option<String>)> {
        validate_agent_principal_page_limit(limit)?;
        let conn = self.conn.lock().unwrap();
        list_agent_principal_grants_page_locked(
            &conn,
            &actor.email,
            agent_creator_authority_kind(actor, source_credential),
            principal_id,
            cursor,
            limit,
        )
    }

    pub fn agent_principal_exists_for_creator(
        &self,
        principal_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT 1 FROM agent_principals
                 WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                   AND publication_pending = 0
                   AND disabled_at IS NULL
                   AND EXISTS (SELECT 1 FROM agent_tokens t
                               WHERE t.principal_id = agent_principals.id
                                 AND t.delegation_kind = 'folder')",
                params![
                    principal_id,
                    &actor.email,
                    agent_creator_authority_kind(actor, source_credential),
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn remove_agent_principal(
        &self,
        principal_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let now = Utc::now().to_rfc3339();
        let receipt = Receipt {
            id: Uuid::now_v7().to_string(),
            kind: "agent_principal.remove".to_string(),
            actor: actor.email.clone(),
            target_id: Some(principal_id.to_string()),
            created_at: now.clone(),
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_source_credential_active(&tx, actor, source_credential)?;
        let active_principal = tx
            .query_row(
                "SELECT 1 FROM agent_principals
                 WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                   AND publication_pending = 0
                   AND disabled_at IS NULL
                   AND EXISTS (SELECT 1 FROM agent_tokens t
                               WHERE t.principal_id = agent_principals.id
                                 AND t.delegation_kind = 'folder')",
                params![principal_id, &actor.email, creator_authority_kind],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !active_principal {
            return Err(ApiError::Forbidden);
        }
        tx.execute(
            "UPDATE agent_principals SET disabled_at = ?4
             WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
               AND disabled_at IS NULL",
            params![principal_id, &actor.email, creator_authority_kind, now],
        )?;
        tx.execute(
            "UPDATE agent_tokens SET revoked_at = ?2
             WHERE principal_id = ?1 AND revoked_at IS NULL",
            params![principal_id, now],
        )?;
        tx.execute(
            "UPDATE agent_folder_grants SET revoked_at = ?2
             WHERE principal_id = ?1 AND revoked_at IS NULL",
            params![principal_id, now],
        )?;
        tx.execute(
            "INSERT INTO receipts (id, kind, actor, target_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &receipt.id,
                &receipt.kind,
                &receipt.actor,
                &receipt.target_id,
                &receipt.created_at,
            ],
        )?;
        tx.execute(
            "INSERT INTO activity (id, kind, actor, target_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                Uuid::now_v7().to_string(),
                &receipt.kind,
                &receipt.actor,
                &receipt.target_id,
                &receipt.created_at,
            ],
        )?;
        record_sync_change_for_receipt(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }

    pub fn list_active_agent_access_for_principal(
        &self,
        principal_id: &str,
        token_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> ApiResult<(Vec<AgentAccess>, Option<String>)> {
        validate_agent_principal_page_limit(limit)?;
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        let mut grants = match cursor {
            Some(cursor) => {
                let sql = format!(
                    "{AGENT_ACCESS_SELECT} WHERE g.principal_id = ?2
                     AND g.revoked_at IS NULL AND p.disabled_at IS NULL AND t.revoked_at IS NULL
                     AND g.publication_pending = 0 AND p.publication_pending = 0
                     AND datetime(g.expires_at) > datetime(?3)
                     AND {ACTIVE_GRANT_CREATOR_PREDICATE}
                     AND datetime(t.expires_at) > datetime(?3) AND g.id > ?4
                     ORDER BY g.id ASC LIMIT ?5"
                );
                let mut statement = conn.prepare(&sql)?;
                let rows = statement.query_map(
                    params![token_id, principal_id, now, cursor, (limit + 1) as i64],
                    row_to_agent_access,
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let sql = format!(
                    "{AGENT_ACCESS_SELECT} WHERE g.principal_id = ?2
                     AND g.revoked_at IS NULL AND p.disabled_at IS NULL AND t.revoked_at IS NULL
                     AND g.publication_pending = 0 AND p.publication_pending = 0
                     AND datetime(g.expires_at) > datetime(?3)
                     AND {ACTIVE_GRANT_CREATOR_PREDICATE}
                     AND datetime(t.expires_at) > datetime(?3)
                     ORDER BY g.id ASC LIMIT ?4"
                );
                let mut statement = conn.prepare(&sql)?;
                let rows = statement.query_map(
                    params![token_id, principal_id, now, (limit + 1) as i64],
                    row_to_agent_access,
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        let has_more = grants.len() > limit;
        grants.truncate(limit);
        if grants.is_empty() && !agent_token_active_locked(&conn, principal_id, token_id)? {
            return Err(ApiError::Forbidden);
        }
        let next_cursor = has_more
            .then(|| grants.last().map(|grant| grant.grant_id.clone()))
            .flatten();
        Ok((grants, next_cursor))
    }

    pub fn get_agent_access(&self, grant_id: &str) -> ApiResult<Option<AgentAccess>> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "{ACCESS_SELECT} WHERE g.id = ?1
             AND g.publication_pending = 0 AND p.publication_pending = 0"
        );
        Ok(conn
            .query_row(&sql, params![grant_id], row_to_agent_access)
            .optional()?)
    }

    pub fn rotate_agent_principal_token(
        &self,
        principal_id: &str,
        token_digest: &str,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AgentPrincipal, Receipt)> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let token_id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("agent_principal.rotate", &actor.email, Some(principal_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_source_credential_active(&tx, actor, source_credential)?;
            let disabled_at = tx
                .query_row(
                    "SELECT disabled_at FROM agent_principals
                     WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                       AND EXISTS (SELECT 1 FROM agent_tokens t
                                   WHERE t.principal_id = agent_principals.id
                                     AND t.delegation_kind = 'folder')",
                    params![principal_id, &actor.email, creator_authority_kind],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .ok_or(ApiError::Forbidden)?;
            if disabled_at.is_some() {
                return Err(ApiError::Validation(
                    "disabled AI agents cannot rotate keys".to_string(),
                ));
            }
            tx.execute(
                "UPDATE agent_tokens SET revoked_at = ?2
                 WHERE principal_id = ?1 AND delegation_kind = 'folder' AND revoked_at IS NULL",
                params![principal_id, now],
            )?;
            tx.execute(
                "INSERT INTO agent_tokens (
                    id, principal_id, token_hash, expires_at, last_used_at,
                    revoked_at, created_at
                ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
                params![token_id, principal_id, token_digest, expires_at, now],
            )?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let principal = {
            let conn = self.conn.lock().unwrap();
            query_agent_principal_page_locked(
                &conn,
                principal_id,
                &actor.email,
                creator_authority_kind,
                DEFAULT_AGENT_PRINCIPAL_PAGE_LIMIT,
            )?
            .ok_or(ApiError::NotFound)?
        };
        Ok((principal, receipt))
    }

    pub fn revoke_agent_access(
        &self,
        grant_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AgentAccess, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("agent_access.revoke", &actor.email, Some(grant_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let workspace_id = tx
                .query_row(
                    "SELECT workspace_id FROM agent_folder_grants WHERE id = ?1",
                    params![grant_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            ensure_workspace_authorized(
                &tx,
                &workspace_id,
                actor,
                source_credential,
                crate::auth::WorkspacePermission::Write,
            )
            .map_err(|error| match error {
                ApiError::Forbidden => ApiError::NotFound,
                other => other,
            })?;
            let changed = tx.execute(
                "UPDATE agent_folder_grants
                 SET revoked_at = COALESCE(revoked_at, ?2) WHERE id = ?1",
                params![grant_id, now],
            )?;
            if changed == 0 {
                return Err(ApiError::NotFound);
            }
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let access = self.get_agent_access(grant_id)?.ok_or(ApiError::NotFound)?;
        Ok((access, receipt))
    }

    pub fn authenticate_agent_token(
        &self,
        token_digest: &str,
        now_epoch: i64,
    ) -> ApiResult<Option<AuthenticatedAgentToken>> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT p.id, p.name, t.id, t.expires_at, t.revoked_at, p.disabled_at
                 FROM agent_tokens t
                 JOIN agent_principals p ON p.id = t.principal_id
                 WHERE t.token_hash = ?1
                   AND t.delegation_kind = 'folder'
                   AND t.publication_pending = 0 AND p.publication_pending = 0",
                params![token_digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((principal_id, principal_name, token_id, expires_at, revoked_at, disabled_at)) =
            row
        else {
            return Ok(None);
        };
        let expires_epoch = DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|_| ApiError::Unauthenticated)?
            .timestamp();
        if revoked_at.is_some() || disabled_at.is_some() || expires_epoch <= now_epoch {
            return Ok(None);
        }
        conn.execute(
            "UPDATE agent_tokens SET last_used_at = ?2 WHERE id = ?1",
            params![token_id, now],
        )?;
        Ok(Some(AuthenticatedAgentToken {
            principal_id,
            principal_name,
            token_id,
        }))
    }

    pub fn authorize_agent_grant(
        &self,
        principal_id: &str,
        token_id: &str,
        grant_id: &str,
        edit: bool,
    ) -> ApiResult<AgentAccess> {
        let conn = self.conn.lock().unwrap();
        active_grant_locked(&conn, principal_id, token_id, grant_id, edit)
    }

    pub fn authorize_agent_file(
        &self,
        principal_id: &str,
        token_id: &str,
        grant_id: &str,
        file_id: &str,
        edit: bool,
    ) -> ApiResult<(AgentAccess, DriveFile)> {
        let conn = self.conn.lock().unwrap();
        let access = active_grant_locked(&conn, principal_id, token_id, grant_id, edit)?;
        let file = ensure_file_in_scope_locked(&conn, &access, file_id, None)?;
        Ok((access, file))
    }

    pub fn agent_tree(
        &self,
        principal_id: &str,
        token_id: &str,
        grant_id: &str,
    ) -> ApiResult<(AgentAccess, Vec<DriveFile>)> {
        let conn = self.conn.lock().unwrap();
        let access = active_grant_locked(&conn, principal_id, token_id, grant_id, false)?;
        ensure_file_in_scope_locked(&conn, &access, &access.root_file_id, None)?;
        let sql = format!(
            "WITH RECURSIVE tree(id, depth, visited) AS (
                 SELECT id, 0, printf('/%s/', id)
                 FROM files WHERE id = ?1 AND workspace_id = ?2 AND trashed = 0
                 UNION ALL
                 SELECT child.id, tree.depth + 1, tree.visited || child.id || '/'
                 FROM files child JOIN tree ON child.parent_id = tree.id
                 WHERE child.workspace_id = ?2 AND child.trashed = 0
                   AND tree.depth < ?3
                   AND instr(tree.visited, printf('/%s/', child.id)) = 0
                 LIMIT ?4
             )
             SELECT {QUALIFIED_FILE_COLUMNS}, tree.depth
             FROM tree JOIN files ON files.id = tree.id"
        );
        let mut statement = conn.prepare(&sql)?;
        let max_depth = i64::try_from(MAX_FILE_TREE_DEPTH + 1).unwrap_or(i64::MAX);
        let max_nodes = i64::try_from(MAX_FILE_TREE_NODES + 1).unwrap_or(i64::MAX);
        let rows = statement.query_map(
            params![
                access.root_file_id,
                access.workspace_id,
                max_depth,
                max_nodes
            ],
            |row| Ok((row_to_file(row)?, row.get::<_, i64>(13)?)),
        )?;
        let mut rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > MAX_FILE_TREE_NODES {
            return Err(ApiError::PayloadTooLarge(format!(
                "agent folder exceeds the {MAX_FILE_TREE_NODES}-item traversal limit"
            )));
        }
        if rows
            .iter()
            .any(|(_, depth)| *depth > MAX_FILE_TREE_DEPTH as i64)
        {
            return Err(ApiError::Validation(format!(
                "agent folder exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
            )));
        }
        rows.sort_by(|(left, _), (right, _)| {
            left.parent_id
                .cmp(&right.parent_id)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok((access, rows.into_iter().map(|(file, _)| file).collect()))
    }

    /// Re-select the granted subtree under the same credential/grant lock and
    /// require every file selected during planning to remain in that subtree.
    pub(crate) fn ensure_agent_tree_publication_authorized(
        &self,
        principal_id: &str,
        token_id: &str,
        grant_id: &str,
        planned_files: &[DriveFile],
    ) -> ApiResult<()> {
        let (_, current_files) = self.agent_tree(principal_id, token_id, grant_id)?;
        if current_files.len() != planned_files.len() {
            return Err(ApiError::Forbidden);
        }
        let current_ids = current_files
            .iter()
            .map(|file| file.id.as_str())
            .collect::<HashSet<_>>();
        if planned_files
            .iter()
            .all(|file| current_ids.contains(file.id.as_str()))
        {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_agent_file(
        &self,
        principal_id: &str,
        token_id: &str,
        grant_id: &str,
        parent_id: Option<&str>,
        name: &str,
        kind: FileKind,
        content_hash: Option<&str>,
        content_bytes: i64,
    ) -> ApiResult<(DriveFile, Receipt)> {
        let access = self.authorize_agent_grant(principal_id, token_id, grant_id, true)?;
        let parent_id = parent_id.unwrap_or(&access.root_file_id);
        let name = validate_file_name(name)?;
        let now = Utc::now().to_rfc3339();
        let size_bytes = matches!(kind, FileKind::File).then_some(content_bytes);
        let mut file = DriveFile {
            id: Uuid::now_v7().to_string(),
            workspace_id: access.workspace_id.clone(),
            parent_id: Some(parent_id.to_string()),
            name,
            kind,
            revision: 1,
            trashed: false,
            starred: false,
            content_hash: content_hash.map(str::to_string),
            created_at: now.clone(),
            updated_at: now.clone(),
            size_bytes,
            folder_size_bytes: None,
            has_cover: false,
        };
        let receipt = new_receipt(
            "agent.file.create",
            &agent_receipt_actor(principal_id, token_id),
            Some(&file.id),
        );
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let active = active_grant_locked(&tx, principal_id, token_id, grant_id, true)?;
            let quota_bytes = tx
                .query_row(
                    "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                    params![&active.workspace_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            let parent = ensure_file_in_scope_locked(&tx, &active, parent_id, None)?;
            if !matches!(parent.kind, FileKind::Folder) {
                return Err(ApiError::Validation("parent must be a folder".to_string()));
            }
            file.parent_id = Some(parent.id);
            file.name = crate::storage::file_destination::available_copy_name_in_tx(
                &tx,
                &active.workspace_id,
                file.parent_id.as_deref(),
                &file.name,
            )?;
            ensure_workspace_node_capacity(&tx, &active.workspace_id, 1)?;
            if let Some(quota_bytes) = quota_bytes {
                enforce_quota_in_txn(&tx, quota_bytes, &active.workspace_id, None, content_bytes)?;
            }
            tx.execute(
                "INSERT INTO files (
                    id, workspace_id, parent_id, name, kind, revision, trashed,
                    starred, content_hash, content_bytes, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 0, 0, ?6, ?7, ?8, ?8)",
                params![
                    file.id,
                    active.workspace_id,
                    file.parent_id,
                    file.name,
                    file.kind.as_db_str(),
                    file.content_hash,
                    content_bytes,
                    now,
                ],
            )?;
            tx.execute(
                "INSERT INTO file_revisions (
                    id, file_id, revision, content_hash, content_bytes,
                    created_at, conflict_of_revision
                 ) VALUES (?1, ?2, 1, ?3, ?4, ?5, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    file.id,
                    file.content_hash,
                    content_bytes,
                    now,
                ],
            )?;
            refresh_file_search_index_locked(&tx, &file.id)?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        self.enqueue_file_background_jobs(&file)?;
        Ok((file, receipt))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put_agent_content(
        &self,
        principal_id: &str,
        token_id: &str,
        grant_id: &str,
        file_id: &str,
        base_revision: i64,
        content_hash: &str,
        content_bytes: i64,
    ) -> ApiResult<(DriveFile, Receipt)> {
        self.authorize_agent_grant(principal_id, token_id, grant_id, true)?;
        let updated_at = Utc::now().to_rfc3339();
        let receipt = new_receipt(
            "agent.file.content",
            &agent_receipt_actor(principal_id, token_id),
            Some(file_id),
        );
        let file = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let active = active_grant_locked(&tx, principal_id, token_id, grant_id, true)?;
            let quota_bytes = tx
                .query_row(
                    "SELECT quota_bytes FROM workspace_policies WHERE workspace_id = ?1",
                    params![&active.workspace_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten();
            let current = ensure_file_in_scope_locked(&tx, &active, file_id, None)?;
            if !matches!(current.kind, FileKind::File) {
                return Err(ApiError::Validation(
                    "content can only be replaced on a file".to_string(),
                ));
            }
            if current.revision != base_revision {
                return Err(ApiError::PreconditionFailed);
            }
            if let Some(quota_bytes) = quota_bytes {
                enforce_quota_in_txn(
                    &tx,
                    quota_bytes,
                    &active.workspace_id,
                    Some(file_id),
                    content_bytes,
                )?;
            }
            let next_revision = current.revision + 1;
            tx.execute(
                "UPDATE files SET revision = ?1, content_hash = ?2,
                                  content_bytes = ?3, updated_at = ?4
                 WHERE id = ?5",
                params![
                    next_revision,
                    content_hash,
                    content_bytes,
                    updated_at,
                    file_id,
                ],
            )?;
            tx.execute(
                "INSERT INTO file_revisions (
                    id, file_id, revision, content_hash, content_bytes,
                    created_at, conflict_of_revision
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    Uuid::now_v7().to_string(),
                    file_id,
                    next_revision,
                    content_hash,
                    content_bytes,
                    updated_at,
                ],
            )?;
            let file = query_file_locked(&tx, file_id)?.ok_or(ApiError::NotFound)?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            file
        };
        self.enqueue_file_background_jobs(&file)?;
        Ok((file, receipt))
    }
}

fn active_grant_locked(
    conn: &Connection,
    principal_id: &str,
    token_id: &str,
    grant_id: &str,
    edit: bool,
) -> ApiResult<AgentAccess> {
    let sql = format!(
        "{AGENT_ACCESS_SELECT} WHERE g.id = ?2 AND g.principal_id = ?3
         AND g.publication_pending = 0 AND p.publication_pending = 0"
    );
    let access = conn
        .query_row(
            &sql,
            params![token_id, grant_id, principal_id],
            row_to_agent_access,
        )
        .optional()?
        .ok_or(ApiError::Forbidden)?;
    if !access.active || (edit && !access.permission.allows_edit()) {
        return Err(ApiError::Forbidden);
    }
    if !agent_grant_creator_authorized_locked(conn, &access)? {
        return Err(ApiError::Forbidden);
    }
    if file_is_effectively_trashed_locked(conn, &access.root_file_id)? {
        return Err(ApiError::Forbidden);
    }
    Ok(access)
}

fn agent_token_active_locked(
    conn: &Connection,
    principal_id: &str,
    token_id: &str,
) -> ApiResult<bool> {
    let token = conn
        .query_row(
            "SELECT t.expires_at, t.revoked_at, p.disabled_at
             FROM agent_tokens t
             JOIN agent_principals p ON p.id = t.principal_id
             WHERE t.id = ?1 AND t.principal_id = ?2
               AND t.publication_pending = 0 AND p.publication_pending = 0",
            params![token_id, principal_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?;
    Ok(token.is_some_and(|(expires_at, revoked_at, disabled_at)| {
        revoked_at.is_none() && disabled_at.is_none() && !is_expired(&expires_at)
    }))
}

/// Persist only an authority class established by the authenticated internal
/// operator path. A matching email string from a local/SSO session or a
/// downshifted operator header remains an ordinary human creator.
fn agent_creator_authority_kind(
    actor: &Actor,
    source_credential: &DriveCredential,
) -> &'static str {
    if actor.email == ADMIN_ACTOR
        && actor.is_admin
        && matches!(actor.auth_mode, AuthMode::Operator)
        && matches!(source_credential, DriveCredential::Operator)
    {
        AGENT_CREATOR_KIND_OPERATOR
    } else {
        AGENT_CREATOR_KIND_USER
    }
}

fn agent_grant_creator_authorized_locked(
    conn: &Connection,
    access: &AgentAccess,
) -> ApiResult<bool> {
    let sql = format!(
        "SELECT EXISTS(
           SELECT 1 FROM agent_folder_grants g
           JOIN agent_principals p ON p.id = g.principal_id
           WHERE g.id = ?1 AND g.principal_id = ?2
             AND {ACTIVE_GRANT_CREATOR_PREDICATE}
         )"
    );
    Ok(conn.query_row(
        &sql,
        params![&access.grant_id, &access.principal_id],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn ensure_file_in_scope_locked(
    conn: &Connection,
    access: &AgentAccess,
    file_id: &str,
    forbidden_ancestor: Option<&str>,
) -> ApiResult<DriveFile> {
    let requested = query_file_locked(conn, file_id)?.ok_or(ApiError::NotFound)?;
    if requested.workspace_id != access.workspace_id || requested.trashed {
        return Err(ApiError::NotFound);
    }
    let mut current = requested.clone();
    let mut visited = HashSet::new();
    for _ in 0..=MAX_FILE_TREE_DEPTH {
        if !visited.insert(current.id.clone()) {
            return Err(ApiError::Validation(
                "file tree contains a parent cycle".to_string(),
            ));
        }
        if forbidden_ancestor.is_some_and(|id| current.id == id) {
            return Err(ApiError::Validation(
                "a folder cannot be moved into itself or its descendants".to_string(),
            ));
        }
        if current.trashed || current.workspace_id != access.workspace_id {
            return Err(ApiError::NotFound);
        }
        if current.id == access.root_file_id {
            if !matches!(current.kind, FileKind::Folder) {
                return Err(ApiError::NotFound);
            }
            return Ok(requested);
        }
        let Some(parent_id) = current.parent_id.as_deref() else {
            return Err(ApiError::NotFound);
        };
        current = query_file_locked(conn, parent_id)?.ok_or(ApiError::NotFound)?;
    }
    Err(ApiError::Validation(format!(
        "file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
    )))
}

fn query_file_locked(conn: &Connection, file_id: &str) -> ApiResult<Option<DriveFile>> {
    let sql = format!("SELECT {FILE_COLUMNS} FROM files WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![file_id], row_to_file)
        .optional()?)
}

fn query_agent_principal_page_locked(
    conn: &Connection,
    principal_id: &str,
    created_by: &str,
    creator_authority_kind: &str,
    grant_limit: usize,
) -> ApiResult<Option<AgentPrincipal>> {
    let principal = conn
        .query_row(
            "SELECT p.id, p.name, p.created_by, p.created_at, p.disabled_at,
                    token.id, token.expires_at, token.last_used_at, token.revoked_at
             FROM agent_principals p
             LEFT JOIN agent_tokens token ON token.id = (
                 SELECT current_token.id FROM agent_tokens current_token
             WHERE current_token.principal_id = p.id
               AND current_token.delegation_kind = 'folder'
               AND current_token.publication_pending = 0
             ORDER BY current_token.created_at DESC, current_token.id DESC LIMIT 1
             )
             WHERE p.id = ?1 AND p.created_by = ?2
               AND p.creator_authority_kind = ?3 AND p.publication_pending = 0
               AND p.disabled_at IS NULL",
            params![principal_id, created_by, creator_authority_kind],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()?;
    let Some((
        principal_id,
        name,
        created_by,
        created_at,
        disabled_at,
        token_id,
        token_expires_at,
        token_last_used_at,
        token_revoked_at,
    )) = principal
    else {
        return Ok(None);
    };
    let (grants, grants_next_cursor) = list_agent_principal_grants_page_locked(
        conn,
        &created_by,
        creator_authority_kind,
        &principal_id,
        None,
        grant_limit,
    )?;
    let active = disabled_at.is_none()
        && token_id.is_some()
        && token_revoked_at.is_none()
        && token_expires_at
            .as_deref()
            .is_some_and(|expires_at| !is_expired(expires_at));
    Ok(Some(AgentPrincipal {
        principal_id,
        name,
        created_by,
        created_at,
        principal_disabled: disabled_at.is_some(),
        token_id,
        token_expires_at,
        token_last_used_at,
        token_revoked_at,
        active,
        grants,
        grants_next_cursor,
    }))
}

fn list_agent_principal_grants_page_locked(
    conn: &Connection,
    created_by: &str,
    creator_authority_kind: &str,
    principal_id: &str,
    cursor: Option<&str>,
    limit: usize,
) -> ApiResult<(Vec<AgentAccess>, Option<String>)> {
    validate_agent_principal_page_limit(limit)?;
    let principal_exists = conn
        .query_row(
            "SELECT 1 FROM agent_principals
             WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
               AND publication_pending = 0
               AND disabled_at IS NULL
               AND EXISTS (SELECT 1 FROM agent_tokens t
                           WHERE t.principal_id = agent_principals.id
                             AND t.delegation_kind = 'folder')",
            params![principal_id, created_by, creator_authority_kind],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !principal_exists {
        return Err(ApiError::Forbidden);
    }
    let mut grants = match cursor {
        Some(cursor) => {
            let sql = format!(
                "{ACCESS_SELECT} WHERE g.principal_id = ?1 AND p.created_by = ?2
                 AND p.creator_authority_kind = ?3
                 AND p.publication_pending = 0 AND g.publication_pending = 0
                 AND g.revoked_at IS NULL AND {ACTIVE_GRANT_CREATOR_PREDICATE}
                 AND g.id > ?4 ORDER BY g.id ASC LIMIT ?5"
            );
            let mut statement = conn.prepare(&sql)?;
            let rows = statement.query_map(
                params![
                    principal_id,
                    created_by,
                    creator_authority_kind,
                    cursor,
                    (limit + 1) as i64,
                ],
                row_to_agent_access,
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        }
        None => {
            let sql = format!(
                "{ACCESS_SELECT} WHERE g.principal_id = ?1 AND p.created_by = ?2
                 AND p.creator_authority_kind = ?3
                 AND p.publication_pending = 0 AND g.publication_pending = 0
                 AND g.revoked_at IS NULL AND {ACTIVE_GRANT_CREATOR_PREDICATE}
                 ORDER BY g.id ASC LIMIT ?4"
            );
            let mut statement = conn.prepare(&sql)?;
            let rows = statement.query_map(
                params![
                    principal_id,
                    created_by,
                    creator_authority_kind,
                    (limit + 1) as i64
                ],
                row_to_agent_access,
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        }
    };
    let has_more = grants.len() > limit;
    grants.truncate(limit);
    let next_cursor = has_more
        .then(|| grants.last().map(|grant| grant.grant_id.clone()))
        .flatten();
    Ok((grants, next_cursor))
}

fn validate_agent_principal_page_limit(limit: usize) -> ApiResult<()> {
    if !(1..=MAX_AGENT_PRINCIPAL_PAGE_LIMIT).contains(&limit) {
        return Err(ApiError::Validation(format!(
            "agent principal limit must be a whole number from 1 to {MAX_AGENT_PRINCIPAL_PAGE_LIMIT}"
        )));
    }
    Ok(())
}

pub(super) fn row_to_agent_access(row: &Row<'_>) -> rusqlite::Result<AgentAccess> {
    let permission = AgentPermission::from_db_str(&row.get::<_, String>(5)?);
    let expires_at: String = row.get(6)?;
    let grant_revoked_at: Option<String> = row.get(7)?;
    let token_expires_at: String = row.get(9)?;
    let token_revoked_at: Option<String> = row.get(11)?;
    let principal_disabled_at: Option<String> = row.get(14)?;
    let active = grant_revoked_at.is_none()
        && token_revoked_at.is_none()
        && principal_disabled_at.is_none()
        && !is_expired(&expires_at)
        && !is_expired(&token_expires_at);
    Ok(AgentAccess {
        principal_id: row.get(0)?,
        name: row.get(1)?,
        grant_id: row.get(2)?,
        workspace_id: row.get(3)?,
        root_file_id: row.get(4)?,
        permission,
        expires_at,
        grant_revoked_at,
        token_id: row.get(8)?,
        token_expires_at,
        token_last_used_at: row.get(10)?,
        token_revoked_at,
        principal_disabled: principal_disabled_at.is_some(),
        created_by: row.get(12)?,
        created_at: row.get(13)?,
        root_name: row.get(15)?,
        workspace_name: row.get(16)?,
        active,
    })
}

pub(super) fn is_expired(value: &str) -> bool {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.timestamp() <= Utc::now().timestamp())
        .unwrap_or(true)
}

fn agent_receipt_actor(principal_id: &str, token_id: &str) -> String {
    format!("agent:{principal_id}:{token_id}")
}

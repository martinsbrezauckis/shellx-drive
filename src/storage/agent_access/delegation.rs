use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{DelegatedAgent, Receipt},
    storage::{authorization, insert_receipt_rows, new_receipt, Storage},
};

use super::{
    agent_creator_authority_kind, delegated_sso_parent_is_active,
    sso_parent::{
        bounded_expiry, principal_matches_source, source_sso_parent_session, SsoParentSession,
        DELEGATION_PARENT_KIND_EXTERNAL_SSO, DELEGATION_PARENT_KIND_LOCAL,
    },
    AuthenticatedDelegatedAgentToken,
};

mod lifecycle;
pub(super) mod limits;
mod logout;
mod revocation;
#[cfg(test)]
mod tests;

use lifecycle::{
    cancel_pending_delegated_agent, delegated_owner_is_admin_locked,
    ensure_delegation_owner_active, is_expired_at_epoch, row_to_delegated_agent,
};
use limits::{ensure_delegated_principal_capacity, ensure_delegated_token_capacity};

/// A secret-bearing delegation remains inert until the route's terminal
/// reauthorization succeeds. The plaintext bearer is never persisted here.
#[derive(Debug)]
pub(crate) struct PendingDelegatedAgentPublication {
    pub(crate) principal_id: String,
    pub(crate) token_id: String,
    pub(crate) receipt: Receipt,
    pub(super) rotation: bool,
    parent_session: Option<SsoParentSession>,
    self_rotation_source_token_id: Option<String>,
}

/// A terminal lifecycle acknowledgement may name a retired delegated bearer
/// only when the mutation captured that exact source/target relationship before
/// changing durable state.
#[derive(Debug, Clone)]
pub(super) struct DelegatedAgentSelfRetirement {
    pub(super) principal_id: String,
    pub(super) source_token_id: String,
    pub(super) retired_at: String,
    pub(super) parent_session: Option<SsoParentSession>,
}

#[derive(Debug, Default)]
pub(crate) struct DelegatedAgentPublicationCompletion {
    pub(super) self_retirement: Option<DelegatedAgentSelfRetirement>,
}

#[derive(Debug, Default)]
pub(crate) struct DelegatedAgentRevocationCompletion {
    pub(super) self_retirement: Option<DelegatedAgentSelfRetirement>,
}

impl Storage {
    pub(crate) fn create_pending_delegated_agent(
        &self,
        name: &str,
        token_digest: &str,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<PendingDelegatedAgentPublication> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let principal_id = Uuid::now_v7().to_string();
        let token_id = Uuid::now_v7().to_string();
        let created_at = Utc::now().to_rfc3339();
        let receipt = new_receipt("agent_delegation.create", &actor.email, Some(&principal_id));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        let parent = source_sso_parent_session(&tx, actor, source_credential)?;
        ensure_delegation_owner_active(&tx, &actor.email, creator_authority_kind, parent.as_ref())?;
        let expires_at = bounded_expiry(expires_at, parent.as_ref())?;
        ensure_delegated_principal_capacity(&tx, &actor.email, creator_authority_kind)?;
        let duplicate_name = if let Some(parent) = parent.as_ref() {
            tx.query_row(
                "SELECT 1 FROM agent_principals p
                 JOIN delegated_agent_parent_sessions b ON b.principal_id = p.id
                 WHERE p.created_by = ?1 AND p.creator_authority_kind = ?2
                   AND p.delegation_parent_kind = 'external_sso'
                   AND b.parent_session_id = ?3
                   AND p.name = ?4 COLLATE NOCASE AND p.disabled_at IS NULL LIMIT 1",
                params![&actor.email, creator_authority_kind, &parent.id, name],
                |_| Ok(()),
            )
        } else {
            tx.query_row(
                "SELECT 1 FROM agent_principals p
                 WHERE p.created_by = ?1 AND p.creator_authority_kind = ?2
                   AND p.delegation_parent_kind = 'local'
                   AND NOT EXISTS (
                       SELECT 1 FROM delegated_agent_parent_sessions b WHERE b.principal_id = p.id
                   )
                   AND p.name = ?3 COLLATE NOCASE AND p.disabled_at IS NULL LIMIT 1",
                params![&actor.email, creator_authority_kind, name],
                |_| Ok(()),
            )
        }
        .optional()?
        .is_some();
        if duplicate_name {
            return Err(ApiError::Validation(
                "an AI agent with this name already exists; select it instead".to_string(),
            ));
        }
        tx.execute(
            "INSERT INTO agent_principals (
                id, name, created_by, creator_authority_kind, delegation_parent_kind, disabled_at,
                created_at,
                publication_pending
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, 1)",
            params![
                &principal_id,
                name,
                &actor.email,
                creator_authority_kind,
                if parent.is_some() {
                    DELEGATION_PARENT_KIND_EXTERNAL_SSO
                } else {
                    DELEGATION_PARENT_KIND_LOCAL
                },
                &created_at,
            ],
        )?;
        tx.execute(
            "INSERT INTO agent_tokens (
                id, principal_id, token_hash, delegation_kind, expires_at, last_used_at,
                revoked_at, created_at, publication_pending
             ) VALUES (?1, ?2, ?3, 'delegated', ?4, NULL, NULL, ?5, 1)",
            params![
                &token_id,
                &principal_id,
                token_digest,
                &expires_at,
                &created_at
            ],
        )?;
        if let Some(parent) = parent.as_ref() {
            tx.execute(
                "INSERT INTO delegated_agent_parent_sessions (
                     principal_id, parent_session_id, owner_email, issuer, subject,
                     parent_token_hash, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &principal_id,
                    &parent.id,
                    &parent.owner_email,
                    &parent.issuer,
                    &parent.subject,
                    &parent.token_hash,
                    &created_at,
                ],
            )?;
        }
        tx.commit()?;
        Ok(PendingDelegatedAgentPublication {
            principal_id,
            token_id,
            receipt,
            rotation: false,
            parent_session: parent,
            self_rotation_source_token_id: None,
        })
    }

    pub(crate) fn stage_delegated_agent_rotation(
        &self,
        principal_id: &str,
        token_digest: &str,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<PendingDelegatedAgentPublication> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let token_id = Uuid::now_v7().to_string();
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("agent_delegation.rotate", &actor.email, Some(principal_id));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        let parent = source_sso_parent_session(&tx, actor, source_credential)?;
        ensure_delegation_owner_active(&tx, &actor.email, creator_authority_kind, parent.as_ref())?;
        let expires_at = bounded_expiry(expires_at, parent.as_ref())?;
        let exists = tx
            .query_row(
                "SELECT 1 FROM agent_principals
                 WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                   AND disabled_at IS NULL AND publication_pending = 0",
                params![principal_id, &actor.email, creator_authority_kind],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
            && principal_matches_source(&tx, principal_id, parent.as_ref())?;
        if !exists {
            return Err(ApiError::NotFound);
        }
        ensure_delegated_token_capacity(&tx, principal_id)?;
        let self_rotation_source_token_id = match source_credential {
            DriveCredential::DelegatedAgentToken(token_id) => tx
                .query_row(
                    "SELECT 1 FROM agent_tokens
                     WHERE id = ?1 AND principal_id = ?2 AND delegation_kind = 'delegated'
                       AND revoked_at IS NULL AND publication_pending = 0",
                    params![token_id, principal_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
                .then(|| token_id.clone()),
            _ => None,
        };
        tx.execute(
            "INSERT INTO agent_tokens (
                id, principal_id, token_hash, delegation_kind, expires_at, last_used_at,
                revoked_at, created_at, publication_pending
             ) VALUES (?1, ?2, ?3, 'delegated', ?4, NULL, NULL, ?5, 1)",
            params![&token_id, principal_id, token_digest, &expires_at, &now],
        )?;
        tx.commit()?;
        Ok(PendingDelegatedAgentPublication {
            principal_id: principal_id.to_string(),
            token_id,
            receipt,
            rotation: true,
            parent_session: parent,
            self_rotation_source_token_id,
        })
    }

    pub(crate) fn publish_pending_delegated_agent(
        &self,
        pending: &PendingDelegatedAgentPublication,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<DelegatedAgentPublicationCompletion> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = (|| {
            authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
            let parent = source_sso_parent_session(&tx, actor, source_credential)?;
            ensure_delegation_owner_active(
                &tx,
                &actor.email,
                creator_authority_kind,
                parent.as_ref(),
            )?;
            if pending.parent_session.as_ref() != parent.as_ref()
                || !principal_matches_source(&tx, &pending.principal_id, parent.as_ref())?
            {
                return Err(ApiError::Unauthenticated);
            }
            let principal_published = if pending.rotation {
                1
            } else {
                tx.execute(
                    "UPDATE agent_principals SET publication_pending = 0
                     WHERE id = ?1 AND created_by = ?2 AND creator_authority_kind = ?3
                       AND disabled_at IS NULL AND publication_pending = 1",
                    params![&pending.principal_id, &actor.email, creator_authority_kind],
                )?
            };
            let self_retirement = if pending.rotation {
                let retired_at = Utc::now().to_rfc3339();
                tx.execute(
                    "UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, ?2)
                     WHERE principal_id = ?1 AND delegation_kind = 'delegated'
                       AND publication_pending = 0",
                    params![&pending.principal_id, &retired_at],
                )?;
                if let Some(source_token_id) = pending.self_rotation_source_token_id.as_ref() {
                    let retired = tx
                        .query_row(
                            "SELECT 1 FROM agent_tokens
                             WHERE id = ?1 AND principal_id = ?2 AND delegation_kind = 'delegated'
                               AND revoked_at = ?3 AND publication_pending = 0",
                            params![source_token_id, &pending.principal_id, &retired_at],
                            |_| Ok(()),
                        )
                        .optional()?
                        .is_some();
                    if !retired {
                        return Err(ApiError::Conflict);
                    }
                    Some(DelegatedAgentSelfRetirement {
                        principal_id: pending.principal_id.clone(),
                        source_token_id: source_token_id.clone(),
                        retired_at,
                        parent_session: pending.parent_session.clone(),
                    })
                } else {
                    None
                }
            } else {
                None
            };
            let token_published = tx.execute(
                "UPDATE agent_tokens SET publication_pending = 0
                 WHERE id = ?1 AND principal_id = ?2 AND delegation_kind = 'delegated'
                   AND revoked_at IS NULL AND publication_pending = 1",
                params![&pending.token_id, &pending.principal_id],
            )?;
            if principal_published != 1 || token_published != 1 {
                return Err(ApiError::Conflict);
            }
            insert_receipt_rows(&tx, &pending.receipt)?;
            Ok(DelegatedAgentPublicationCompletion { self_retirement })
        })();
        match result {
            Ok(completion) => {
                tx.commit()?;
                Ok(completion)
            }
            Err(error) => {
                cancel_pending_delegated_agent(&tx, pending, &actor.email)?;
                tx.commit()?;
                Err(error)
            }
        }
    }
}

impl Storage {
    pub fn create_delegated_agent(
        &self,
        name: &str,
        token_digest: &str,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DelegatedAgent, Receipt)> {
        let pending = self.create_pending_delegated_agent(
            name,
            token_digest,
            expires_at,
            actor,
            source_credential,
        )?;
        self.publish_pending_delegated_agent(&pending, actor, source_credential)?;
        let agent = self.get_current_delegated_agent_for_owner(
            &pending.principal_id,
            actor,
            source_credential,
        )?;
        Ok((agent, pending.receipt))
    }

    pub fn list_delegated_agents_for_owner(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
        cursor: Option<&str>,
        limit: usize,
    ) -> ApiResult<(Vec<DelegatedAgent>, Option<String>)> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        let parent = source_sso_parent_session(&tx, actor, source_credential)?;
        let scope = if parent.is_some() {
            "AND p.delegation_parent_kind = 'external_sso' AND EXISTS (
                SELECT 1 FROM delegated_agent_parent_sessions b
                WHERE b.principal_id = p.id AND b.parent_session_id = ?3
                  AND b.owner_email = ?1 AND b.issuer = ?4 AND b.subject = ?5
                  AND b.parent_token_hash = ?6
             )"
        } else {
            "AND p.delegation_parent_kind = 'local' AND ?3 IS NULL AND ?4 IS NULL
              AND ?5 IS NULL AND ?6 IS NULL AND NOT EXISTS (
                SELECT 1 FROM delegated_agent_parent_sessions b WHERE b.principal_id = p.id
             )"
        };
        let query = format!(
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
             WHERE p.created_by = ?1 AND p.creator_authority_kind = ?2
               AND p.publication_pending = 0
             {scope} AND (?7 IS NULL OR p.id < ?7)
             ORDER BY p.id DESC LIMIT ?8"
        );
        let agents = {
            let mut statement = tx.prepare(&query)?;
            let rows = statement.query_map(
                params![
                    &actor.email,
                    creator_authority_kind,
                    parent.as_ref().map(|parent| parent.id.as_str()),
                    parent.as_ref().map(|parent| parent.issuer.as_str()),
                    parent.as_ref().map(|parent| parent.subject.as_str()),
                    parent.as_ref().map(|parent| parent.token_hash.as_str()),
                    cursor,
                    (limit + 1) as i64,
                ],
                |row| row_to_delegated_agent(row, parent.is_none() && actor.is_admin),
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.commit()?;
        let mut agents = agents;
        let has_more = agents.len() > limit;
        agents.truncate(limit);
        let next_cursor = has_more
            .then(|| agents.last().map(|agent| agent.principal_id.clone()))
            .flatten();
        Ok((agents, next_cursor))
    }

    pub fn rotate_delegated_agent_token(
        &self,
        principal_id: &str,
        token_digest: &str,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DelegatedAgent, Receipt)> {
        let pending = self.stage_delegated_agent_rotation(
            principal_id,
            token_digest,
            expires_at,
            actor,
            source_credential,
        )?;
        self.publish_pending_delegated_agent(&pending, actor, source_credential)?;
        let agent =
            self.get_current_delegated_agent_for_owner(principal_id, actor, source_credential)?;
        Ok((agent, pending.receipt))
    }

    /// Authenticate only a deliberately issued account-wide delegation. A
    /// legacy folder token never reaches this path, even if the bearer prefix
    /// is the same.
    pub fn authenticate_delegated_agent_token(
        &self,
        token_digest: &str,
        now_epoch: i64,
    ) -> ApiResult<Option<AuthenticatedDelegatedAgentToken>> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let row = tx
            .query_row(
                "SELECT p.id, p.created_by, p.creator_authority_kind, p.delegation_parent_kind,
                        t.id, t.expires_at, t.revoked_at, p.disabled_at
                 FROM agent_tokens t
                 JOIN agent_principals p ON p.id = t.principal_id
                 WHERE t.token_hash = ?1 AND t.delegation_kind = 'delegated'
                   AND t.publication_pending = 0 AND p.publication_pending = 0",
                params![token_digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            principal_id,
            owner_email,
            owner_authority_kind,
            parent_kind,
            token_id,
            expires_at,
            revoked_at,
            disabled_at,
        )) = row
        else {
            return Ok(None);
        };
        if revoked_at.is_some()
            || disabled_at.is_some()
            || is_expired_at_epoch(&expires_at, now_epoch)
        {
            return Ok(None);
        }
        let owner_is_admin = match parent_kind.as_str() {
            DELEGATION_PARENT_KIND_EXTERNAL_SSO => {
                if !delegated_sso_parent_is_active(&tx, &principal_id, &owner_email)? {
                    return Ok(None);
                }
                false
            }
            DELEGATION_PARENT_KIND_LOCAL => {
                if delegated_sso_parent_is_active(&tx, &principal_id, &owner_email)? {
                    return Ok(None);
                }
                let Some(owner_is_admin) =
                    delegated_owner_is_admin_locked(&tx, &owner_email, &owner_authority_kind)?
                else {
                    return Ok(None);
                };
                owner_is_admin
            }
            _ => return Ok(None),
        };
        tx.execute(
            "UPDATE agent_tokens SET last_used_at = ?2 WHERE id = ?1",
            params![&token_id, &now],
        )?;
        tx.commit()?;
        Ok(Some(AuthenticatedDelegatedAgentToken {
            principal_id,
            owner_email,
            owner_is_admin,
            token_id,
        }))
    }
}

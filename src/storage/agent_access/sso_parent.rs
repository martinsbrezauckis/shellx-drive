use chrono::DateTime;
use rusqlite::{params, OptionalExtension, Transaction};

use crate::{
    auth::{Actor, AuthMode, DriveCredential},
    error::{ApiError, ApiResult},
};

const LOCAL_PASSWORD_ISSUER: &str = "local-password";
pub(super) const DELEGATION_PARENT_KIND_LOCAL: &str = "local";
pub(super) const DELEGATION_PARENT_KIND_EXTERNAL_SSO: &str = "external_sso";

/// A delegated external identity inherits only a live, exact parent session.
/// The raw bearer and any provider role claim remain outside durable storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SsoParentSession {
    pub(super) id: String,
    pub(super) owner_email: String,
    pub(super) issuer: String,
    pub(super) subject: String,
    pub(super) token_hash: String,
    pub(super) expires_at: String,
}

pub(super) fn source_sso_parent_session(
    tx: &Transaction<'_>,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<Option<SsoParentSession>> {
    match source_credential {
        DriveCredential::UserSession(session_id) if actor.auth_mode == AuthMode::Sso => {
            active_parent_session(tx, session_id, &actor.email, None).map(Some)
        }
        DriveCredential::DelegatedAgentToken(token_id)
            if actor.auth_mode == AuthMode::DelegatedAgent =>
        {
            let binding = tx
                .query_row(
                    "SELECT b.parent_session_id, b.owner_email, b.issuer, b.subject,
                            b.parent_token_hash
                     FROM delegated_agent_parent_sessions b
                     JOIN agent_principals p ON p.id = b.principal_id
                     JOIN agent_tokens t ON t.principal_id = p.id
                     WHERE t.id = ?1 AND t.delegation_kind = 'delegated'
                       AND p.delegation_parent_kind = 'external_sso'
                       AND p.created_by = ?2 AND b.owner_email = ?2",
                    params![token_id, &actor.email],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((session_id, owner_email, issuer, subject, token_hash)) = binding else {
                return Ok(None);
            };
            active_parent_session(
                tx,
                &session_id,
                &owner_email,
                Some((&issuer, &subject, &token_hash)),
            )
            .map(Some)
        }
        _ => Ok(None),
    }
}

pub(crate) fn delegated_sso_parent_is_active(
    tx: &Transaction<'_>,
    principal_id: &str,
    owner_email: &str,
) -> ApiResult<bool> {
    let binding = tx
        .query_row(
            "SELECT parent_session_id, owner_email, issuer, subject, parent_token_hash
             FROM delegated_agent_parent_sessions WHERE principal_id = ?1",
            [principal_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((session_id, binding_owner, issuer, subject, token_hash)) = binding else {
        return Ok(false);
    };
    if binding_owner != owner_email {
        return Err(ApiError::Unauthenticated);
    }
    active_parent_session(
        tx,
        &session_id,
        owner_email,
        Some((&issuer, &subject, &token_hash)),
    )?;
    Ok(true)
}

pub(super) fn principal_matches_source(
    tx: &Transaction<'_>,
    principal_id: &str,
    parent: Option<&SsoParentSession>,
) -> ApiResult<bool> {
    if let Some(parent) = parent {
        return Ok(tx
            .query_row(
                "SELECT 1 FROM delegated_agent_parent_sessions b
                 JOIN agent_principals p ON p.id = b.principal_id
                 WHERE b.principal_id = ?1 AND b.parent_session_id = ?2
                   AND b.owner_email = ?3 AND b.issuer = ?4 AND b.subject = ?5
                   AND b.parent_token_hash = ?6
                   AND p.delegation_parent_kind = 'external_sso'",
                params![
                    principal_id,
                    &parent.id,
                    &parent.owner_email,
                    &parent.issuer,
                    &parent.subject,
                    &parent.token_hash,
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some());
    }
    Ok(tx
        .query_row(
            "SELECT 1 FROM agent_principals p
             WHERE p.id = ?1 AND p.delegation_parent_kind = 'local'
               AND NOT EXISTS (
                   SELECT 1 FROM delegated_agent_parent_sessions b WHERE b.principal_id = p.id
               )",
            [principal_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(super) fn bounded_expiry(
    requested_expires_at: &str,
    parent: Option<&SsoParentSession>,
) -> ApiResult<String> {
    let requested = DateTime::parse_from_rfc3339(requested_expires_at)
        .map_err(|_| ApiError::Validation("invalid delegated token expiry".to_string()))?;
    let Some(parent) = parent else {
        return Ok(requested_expires_at.to_string());
    };
    let parent_expires_at =
        DateTime::parse_from_rfc3339(&parent.expires_at).map_err(|_| ApiError::Unauthenticated)?;
    Ok(if requested > parent_expires_at {
        parent.expires_at.clone()
    } else {
        requested_expires_at.to_string()
    })
}

fn active_parent_session(
    tx: &Transaction<'_>,
    session_id: &str,
    owner_email: &str,
    identity: Option<(&str, &str, &str)>,
) -> ApiResult<SsoParentSession> {
    let now = chrono::Utc::now().to_rfc3339();
    let session = tx
        .query_row(
            "SELECT id, actor_email, issuer, subject, token_hash, expires_at
             FROM auth_sessions
             WHERE id = ?1 AND actor_email = ?2 AND issuer <> ?3
               AND revoked_at IS NULL AND publication_pending = 0
               AND julianday(expires_at) > julianday(?4)",
            params![session_id, owner_email, LOCAL_PASSWORD_ISSUER, &now],
            |row| {
                Ok(SsoParentSession {
                    id: row.get(0)?,
                    owner_email: row.get(1)?,
                    issuer: row.get(2)?,
                    subject: row.get(3)?,
                    token_hash: row.get(4)?,
                    expires_at: row.get(5)?,
                })
            },
        )
        .optional()?
        .ok_or(ApiError::Unauthenticated)?;
    if identity.is_some_and(|(issuer, subject, token_hash)| {
        session.owner_email != owner_email
            || session.issuer != issuer
            || session.subject != subject
            || session.token_hash != token_hash
    }) {
        return Err(ApiError::Unauthenticated);
    }
    Ok(session)
}

#[cfg(test)]
mod tests;

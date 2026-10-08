use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction};

use crate::{
    auth::{Actor, AuthMode, DriveCredential},
    error::{ApiError, ApiResult},
    storage::{authorization, Storage},
};

use super::super::super::{agent_creator_authority_kind, sso_parent};
use super::super::{DelegatedAgentRevocationCompletion, DelegatedAgentSelfRetirement};
use super::{delegated_owner_is_admin_locked, ensure_delegation_owner_active};

impl Storage {
    /// A self-revoking delegated bearer is intentionally inactive at the
    /// route's terminal boundary. Admit that acknowledgement only when the
    /// exact authenticated source/target retirement was captured in the
    /// durable mutation; every non-self caller retains normal source liveness.
    pub(crate) fn ensure_delegated_agent_revocation_publication_authorized(
        &self,
        principal_id: &str,
        completion: &DelegatedAgentRevocationCompletion,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        if let Some(retirement) = completion.self_retirement.as_ref() {
            if retirement.principal_id != principal_id {
                return Err(ApiError::Unauthenticated);
            }
            ensure_self_delegated_lifecycle_completion(
                &tx,
                retirement,
                None,
                true,
                actor,
                source_credential,
            )?;
        } else {
            authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        }
        tx.commit()?;
        Ok(())
    }
}

pub(super) fn ensure_self_delegated_lifecycle_completion(
    tx: &Transaction<'_>,
    retirement: &DelegatedAgentSelfRetirement,
    expected_new_token_id: Option<&str>,
    principal_disabled: bool,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    let DriveCredential::DelegatedAgentToken(source_token_id) = source_credential else {
        return Err(ApiError::Unauthenticated);
    };
    if actor.auth_mode != AuthMode::DelegatedAgent || source_token_id != &retirement.source_token_id
    {
        return Err(ApiError::Unauthenticated);
    }

    let now = Utc::now().to_rfc3339();
    let (owner_email, owner_authority_kind, parent_kind, disabled_at): (
        String,
        String,
        String,
        Option<String>,
    ) = tx
        .query_row(
            "SELECT p.created_by, p.creator_authority_kind, p.delegation_parent_kind,
                    p.disabled_at
             FROM agent_tokens source
             JOIN agent_principals p ON p.id = source.principal_id
             WHERE source.id = ?1 AND source.principal_id = ?2
               AND source.delegation_kind = 'delegated' AND source.revoked_at = ?3
               AND source.publication_pending = 0 AND p.publication_pending = 0
               AND julianday(source.expires_at) > julianday(?4)",
            params![
                &retirement.source_token_id,
                &retirement.principal_id,
                &retirement.retired_at,
                &now,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?
        .ok_or(ApiError::Unauthenticated)?;
    if disabled_at.is_some() != principal_disabled
        || (principal_disabled && disabled_at.as_deref() != Some(retirement.retired_at.as_str()))
        || owner_email != actor.email
        || owner_authority_kind != agent_creator_authority_kind(actor, source_credential)
    {
        return Err(ApiError::Unauthenticated);
    }
    if let Some(new_token_id) = expected_new_token_id {
        let new_token_live = tx
            .query_row(
                "SELECT 1 FROM agent_tokens
                 WHERE id = ?1 AND principal_id = ?2 AND delegation_kind = 'delegated'
                   AND revoked_at IS NULL AND publication_pending = 0
                   AND julianday(expires_at) > julianday(?3)",
                params![new_token_id, &retirement.principal_id, &now],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !new_token_live {
            return Err(ApiError::Unauthenticated);
        }
    }

    let parent = sso_parent::source_sso_parent_session(tx, actor, source_credential)?;
    if retirement.parent_session.as_ref() != parent.as_ref()
        || !sso_parent::principal_matches_source(tx, &retirement.principal_id, parent.as_ref())?
    {
        return Err(ApiError::Unauthenticated);
    }
    ensure_delegation_owner_active(tx, &actor.email, &owner_authority_kind, parent.as_ref())?;
    if parent_kind == "external_sso" {
        if actor.is_admin || parent.is_none() {
            return Err(ApiError::Forbidden);
        }
    } else if parent_kind == "local" {
        if parent.is_some() {
            return Err(ApiError::Unauthenticated);
        }
        let current_is_admin =
            delegated_owner_is_admin_locked(tx, &owner_email, &owner_authority_kind)?
                .ok_or(ApiError::Unauthenticated)?;
        if actor.is_admin && !current_is_admin {
            return Err(ApiError::Forbidden);
        }
    } else {
        return Err(ApiError::Unauthenticated);
    }
    Ok(())
}

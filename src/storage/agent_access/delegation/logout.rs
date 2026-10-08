use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::Actor,
    error::{ApiError, ApiResult},
    model::{DelegatedAgent, Receipt},
    storage::{insert_receipt_rows, new_receipt, Storage},
};

use super::super::{
    delegated_sso_parent_is_active,
    sso_parent::{DELEGATION_PARENT_KIND_EXTERNAL_SSO, DELEGATION_PARENT_KIND_LOCAL},
};
use super::lifecycle::ensure_delegation_owner_active;

impl Storage {
    /// An account-wide agent signs out by retiring its exact bearer. This is
    /// intentionally not modeled as a human browser session.
    pub(crate) fn revoke_delegated_agent_token_for_actor(
        &self,
        token_id: &str,
        actor: &Actor,
    ) -> ApiResult<(DelegatedAgent, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt("agent_delegation.logout", &actor.email, Some(token_id));
        let (principal_id, owner_authority_kind) = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let owner = tx
                .query_row(
                    "SELECT p.id, p.creator_authority_kind, p.delegation_parent_kind
                     FROM agent_tokens t
                     JOIN agent_principals p ON p.id = t.principal_id
                     WHERE t.id = ?1 AND t.delegation_kind = 'delegated'
                       AND t.revoked_at IS NULL AND p.disabled_at IS NULL
                       AND t.publication_pending = 0 AND p.publication_pending = 0
                       AND p.created_by = ?2",
                    params![token_id, &actor.email],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or(ApiError::Unauthenticated)?;
            match owner.2.as_str() {
                DELEGATION_PARENT_KIND_EXTERNAL_SSO => {
                    if !delegated_sso_parent_is_active(&tx, &owner.0, &actor.email)? {
                        return Err(ApiError::Unauthenticated);
                    }
                }
                DELEGATION_PARENT_KIND_LOCAL => {
                    if delegated_sso_parent_is_active(&tx, &owner.0, &actor.email)? {
                        return Err(ApiError::Unauthenticated);
                    }
                    ensure_delegation_owner_active(&tx, &actor.email, &owner.1, None)?;
                }
                _ => return Err(ApiError::Unauthenticated),
            }
            let revoked = tx.execute(
                "UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, ?2)
                 WHERE id = ?1 AND delegation_kind = 'delegated'",
                params![token_id, &now],
            )?;
            if revoked != 1 {
                return Err(ApiError::Unauthenticated);
            }
            tx.execute(
                "UPDATE office_edit_sessions SET used_at = COALESCE(used_at, ?2)
                 WHERE source_credential_kind = 'delegated_agent'
                   AND source_credential_id = ?1 AND actor_email = ?3
                   AND used_at IS NULL",
                params![token_id, &now, &actor.email],
            )?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
            (owner.0, owner.1)
        };
        let agent = self
            .get_delegated_agent_for_owner(&principal_id, &actor.email, &owner_authority_kind)?
            .ok_or(ApiError::NotFound)?;
        Ok((agent, receipt))
    }
}

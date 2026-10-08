use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{DelegatedAgent, Receipt},
    storage::{authorization, Storage},
};

use super::super::{
    agent_creator_authority_kind,
    sso_parent::{principal_matches_source, source_sso_parent_session},
};
use super::{DelegatedAgentRevocationCompletion, DelegatedAgentSelfRetirement};

impl Storage {
    pub(crate) fn revoke_delegated_agent(
        &self,
        principal_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DelegatedAgent, Receipt, DelegatedAgentRevocationCompletion)> {
        let creator_authority_kind = agent_creator_authority_kind(actor, source_credential);
        let now = Utc::now().to_rfc3339();
        let completion = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
            let parent = source_sso_parent_session(&tx, actor, source_credential)?;
            if !principal_matches_source(&tx, principal_id, parent.as_ref())? {
                return Err(ApiError::NotFound);
            }
            let self_retirement_source_token_id = match source_credential {
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
            let updated = tx.execute(
                "UPDATE agent_principals SET disabled_at = COALESCE(disabled_at, ?1)
                 WHERE id = ?2 AND created_by = ?3 AND creator_authority_kind = ?4
                   AND publication_pending = 0",
                params![&now, principal_id, &actor.email, creator_authority_kind],
            )?;
            if updated == 0 {
                return Err(ApiError::NotFound);
            }
            tx.execute(
                "UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, ?1)
                 WHERE principal_id = ?2 AND delegation_kind = 'delegated'",
                params![&now, principal_id],
            )?;
            let self_retirement = if let Some(source_token_id) = self_retirement_source_token_id {
                let retired = tx
                    .query_row(
                        "SELECT 1 FROM agent_tokens
                         JOIN agent_principals p ON p.id = agent_tokens.principal_id
                         WHERE agent_tokens.id = ?1 AND agent_tokens.principal_id = ?2
                           AND agent_tokens.delegation_kind = 'delegated'
                           AND agent_tokens.revoked_at = ?3
                           AND agent_tokens.publication_pending = 0
                           AND p.disabled_at = ?3 AND p.publication_pending = 0",
                        params![&source_token_id, principal_id, &now],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !retired {
                    return Err(ApiError::Conflict);
                }
                Some(DelegatedAgentSelfRetirement {
                    principal_id: principal_id.to_string(),
                    source_token_id,
                    retired_at: now.clone(),
                    parent_session: parent,
                })
            } else {
                None
            };
            if self_retirement.is_none() {
                authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
            }
            tx.commit()?;
            DelegatedAgentRevocationCompletion { self_retirement }
        };
        let agent = self
            .get_delegated_agent_for_owner(principal_id, &actor.email, creator_authority_kind)?
            .ok_or(ApiError::NotFound)?;
        let receipt =
            self.insert_receipt("agent_delegation.revoke", &actor.email, Some(principal_id))?;
        Ok((agent, receipt, completion))
    }
}

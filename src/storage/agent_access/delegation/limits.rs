use chrono::{Duration, Utc};
use rusqlite::{params, Transaction};

use crate::error::{ApiError, ApiResult};

pub(in crate::storage::agent_access) const MAX_ACTIVE_DELEGATED_AGENTS_PER_OWNER: i64 = 50;
pub(in crate::storage::agent_access) const MAX_DELEGATED_AGENTS_PER_OWNER: i64 = 200;
pub(in crate::storage::agent_access) const MAX_DELEGATED_TOKENS_PER_PRINCIPAL: i64 = 64;
pub(in crate::storage::agent_access) const RETIRED_DELEGATION_RETENTION_DAYS: i64 = 365;

pub(super) fn ensure_delegated_principal_capacity(
    tx: &Transaction<'_>,
    owner_email: &str,
    creator_authority_kind: &str,
) -> ApiResult<()> {
    let (mut total, active): (i64, i64) = tx.query_row(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE disabled_at IS NULL)
             FROM agent_principals
             WHERE created_by = ?1 AND creator_authority_kind = ?2
               AND EXISTS (SELECT 1 FROM agent_tokens t
                           WHERE t.principal_id = agent_principals.id
                             AND t.delegation_kind = 'delegated')",
        params![owner_email, creator_authority_kind],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if total >= MAX_DELEGATED_AGENTS_PER_OWNER {
        // Keep revocation evidence for a year. Never erase a bearer that a
        // backup job or an Office edit session still names, even if used.
        let cutoff = (Utc::now() - Duration::days(RETIRED_DELEGATION_RETENTION_DAYS)).to_rfc3339();
        tx.execute(
                "DELETE FROM agent_principals WHERE id IN (
                    SELECT p.id FROM agent_principals p
                    WHERE p.created_by = ?1 AND p.creator_authority_kind = ?2
                      AND p.disabled_at IS NOT NULL AND p.disabled_at < ?3
                      AND EXISTS (SELECT 1 FROM agent_tokens t WHERE t.principal_id = p.id AND t.delegation_kind = 'delegated')
                      AND NOT EXISTS (SELECT 1 FROM agent_tokens t WHERE t.principal_id = p.id AND t.revoked_at IS NULL)
                      AND NOT EXISTS (SELECT 1 FROM agent_folder_grants g WHERE g.principal_id = p.id)
                      AND NOT EXISTS (
                          SELECT 1 FROM agent_tokens t JOIN office_edit_sessions s
                            ON s.source_credential_kind = 'delegated_agent' AND s.source_credential_id = t.id
                          WHERE t.principal_id = p.id
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM agent_tokens t JOIN backup_jobs b
                            ON b.source_credential_kind = 'delegated_agent' AND b.source_credential_id = t.id
                          WHERE t.principal_id = p.id
                      )
                    ORDER BY p.disabled_at ASC, p.id ASC LIMIT 25
                )",
                params![owner_email, creator_authority_kind, &cutoff],
            )?;
        total = tx.query_row(
                "SELECT COUNT(*) FROM agent_principals p WHERE p.created_by = ?1
                   AND p.creator_authority_kind = ?2 AND EXISTS (
                     SELECT 1 FROM agent_tokens t WHERE t.principal_id = p.id AND t.delegation_kind = 'delegated')",
                params![owner_email, creator_authority_kind],
                |row| row.get(0),
            )?;
    }
    if total >= MAX_DELEGATED_AGENTS_PER_OWNER || active >= MAX_ACTIVE_DELEGATED_AGENTS_PER_OWNER {
        return Err(ApiError::PayloadTooLarge(
                "account-wide AI agent quota reached; revoke unused active agents or wait for retained history to expire".to_string(),
            ));
    }
    Ok(())
}

pub(super) fn ensure_delegated_token_capacity(
    tx: &Transaction<'_>,
    principal_id: &str,
) -> ApiResult<()> {
    let mut token_count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM agent_tokens
             WHERE principal_id = ?1 AND delegation_kind = 'delegated'",
        params![principal_id],
        |row| row.get(0),
    )?;
    if token_count >= MAX_DELEGATED_TOKENS_PER_PRINCIPAL {
        let cutoff = (Utc::now() - Duration::days(RETIRED_DELEGATION_RETENTION_DAYS)).to_rfc3339();
        tx.execute(
            "DELETE FROM agent_tokens WHERE id IN (
                    SELECT t.id FROM agent_tokens t
                    WHERE t.principal_id = ?1 AND t.delegation_kind = 'delegated'
                      AND t.revoked_at IS NOT NULL AND t.revoked_at < ?2
                      AND NOT EXISTS (SELECT 1 FROM office_edit_sessions s
                                      WHERE s.source_credential_kind = 'delegated_agent'
                                        AND s.source_credential_id = t.id)
                      AND NOT EXISTS (SELECT 1 FROM backup_jobs b
                                      WHERE b.source_credential_kind = 'delegated_agent'
                                        AND b.source_credential_id = t.id)
                    ORDER BY t.revoked_at ASC, t.id ASC LIMIT 25
                )",
            params![principal_id, &cutoff],
        )?;
        token_count = tx.query_row(
                "SELECT COUNT(*) FROM agent_tokens WHERE principal_id = ?1 AND delegation_kind = 'delegated'",
                params![principal_id],
                |row| row.get(0),
            )?;
    }
    if token_count >= MAX_DELEGATED_TOKENS_PER_PRINCIPAL {
        return Err(ApiError::PayloadTooLarge(
            "account-wide AI agent key history reached its retention limit".to_string(),
        ));
    }
    Ok(())
}

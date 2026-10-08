use chrono::{Duration, Utc};
use rusqlite::{params, Transaction};

use crate::error::{ApiError, ApiResult};

use super::super::delegation::limits::{
    MAX_ACTIVE_DELEGATED_AGENTS_PER_OWNER, MAX_DELEGATED_AGENTS_PER_OWNER,
    MAX_DELEGATED_TOKENS_PER_PRINCIPAL, RETIRED_DELEGATION_RETENTION_DAYS,
};

pub(super) const MAX_FOLDER_GRANTS_PER_PRINCIPAL: i64 = MAX_DELEGATED_TOKENS_PER_PRINCIPAL;

/// Count the stable creator identity, including all authority kinds and pending
/// rows. Replacing a browser session or changing its authority cannot reset
/// this retained allocation budget. Folder and account-wide agents share the
/// creator's principal budget; token/grant budgets also count pending rows.
pub(super) fn ensure_principal_capacity(tx: &Transaction<'_>, creator: &str) -> ApiResult<()> {
    let counts = |tx: &Transaction<'_>| {
        tx.query_row(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE disabled_at IS NULL)
             FROM agent_principals WHERE created_by = ?1",
            [creator],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
    };
    let (mut total, active) = counts(tx)?;
    if total >= MAX_DELEGATED_AGENTS_PER_OWNER {
        let cutoff = retired_cutoff();
        // Cascade only a wholly retired folder principal. Preserve pending,
        // mixed-kind, live, recent, and externally referenced evidence even
        // when that means refusing a new allocation at capacity.
        tx.execute(
            "DELETE FROM agent_principals WHERE id IN (
                SELECT p.id FROM agent_principals p
                WHERE p.created_by = ?1 AND p.publication_pending = 0
                  AND p.disabled_at IS NOT NULL AND p.disabled_at < ?2
                  AND EXISTS (SELECT 1 FROM agent_tokens t WHERE t.principal_id = p.id)
                  AND NOT EXISTS (SELECT 1 FROM agent_tokens t WHERE t.principal_id = p.id
                      AND (t.delegation_kind != 'folder' OR t.publication_pending != 0
                           OR t.revoked_at IS NULL OR t.revoked_at >= ?2))
                  AND NOT EXISTS (SELECT 1 FROM agent_folder_grants g WHERE g.principal_id = p.id
                      AND (g.publication_pending != 0 OR g.revoked_at IS NULL OR g.revoked_at >= ?2))
                  AND NOT EXISTS (SELECT 1 FROM office_edit_sessions s
                      WHERE s.source_credential_id = p.id
                         OR s.source_credential_id IN (SELECT id FROM agent_tokens WHERE principal_id = p.id)
                         OR s.source_credential_id IN (SELECT id FROM agent_folder_grants WHERE principal_id = p.id))
                  AND NOT EXISTS (SELECT 1 FROM backup_jobs b
                      WHERE b.source_credential_id = p.id
                         OR b.source_credential_id IN (SELECT id FROM agent_tokens WHERE principal_id = p.id)
                         OR b.source_credential_id IN (SELECT id FROM agent_folder_grants WHERE principal_id = p.id))
                ORDER BY p.disabled_at, p.id LIMIT 25
            )",
            params![creator, cutoff],
        )?;
        total = counts(tx)?.0;
    }
    if total >= MAX_DELEGATED_AGENTS_PER_OWNER || active >= MAX_ACTIVE_DELEGATED_AGENTS_PER_OWNER {
        return Err(ApiError::PayloadTooLarge(
            "AI agent principal history reached its retention limit".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_token_capacity(tx: &Transaction<'_>, principal_id: &str) -> ApiResult<()> {
    let count = |tx: &Transaction<'_>| {
        tx.query_row(
            "SELECT COUNT(*) FROM agent_tokens WHERE principal_id = ?1",
            [principal_id],
            |row| row.get::<_, i64>(0),
        )
    };
    if count(tx)? >= MAX_DELEGATED_TOKENS_PER_PRINCIPAL {
        tx.execute(
            "DELETE FROM agent_tokens WHERE id IN (
                SELECT t.id FROM agent_tokens t
                WHERE t.principal_id = ?1 AND t.delegation_kind = 'folder'
                  AND t.publication_pending = 0 AND t.revoked_at IS NOT NULL AND t.revoked_at < ?2
                  AND NOT EXISTS (SELECT 1 FROM office_edit_sessions s WHERE s.source_credential_id = t.id)
                  AND NOT EXISTS (SELECT 1 FROM backup_jobs b WHERE b.source_credential_id = t.id)
                ORDER BY t.revoked_at, t.id LIMIT 25
            )",
            params![principal_id, retired_cutoff()],
        )?;
    }
    if count(tx)? >= MAX_DELEGATED_TOKENS_PER_PRINCIPAL {
        return Err(ApiError::PayloadTooLarge(
            "AI agent key history reached its retention limit".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_grant_capacity(
    tx: &Transaction<'_>,
    principal_id: &str,
    grant_id: &str,
) -> ApiResult<()> {
    // A same-row regrant allocates no history. Do not prune the row selected
    // for reuse or any retired row still named by another security operation.
    let allocation = tx.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM agent_folder_grants WHERE id = ?1)",
        [grant_id],
        |row| row.get::<_, bool>(0),
    )?;
    if !allocation {
        return Ok(());
    }
    tx.execute(
        "DELETE FROM agent_folder_grants WHERE id IN (
            SELECT g.id FROM agent_folder_grants g
            WHERE g.principal_id = ?1 AND g.publication_pending = 0
              AND g.revoked_at IS NOT NULL AND g.revoked_at < ?2
              AND NOT EXISTS (SELECT 1 FROM office_edit_sessions s WHERE s.source_credential_id = g.id)
              AND NOT EXISTS (SELECT 1 FROM backup_jobs b WHERE b.source_credential_id = g.id)
            ORDER BY g.revoked_at, g.id LIMIT 25
        )",
        params![principal_id, retired_cutoff()],
    )?;
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM agent_folder_grants WHERE principal_id = ?1",
        [principal_id],
        |row| row.get(0),
    )?;
    if count >= MAX_FOLDER_GRANTS_PER_PRINCIPAL {
        return Err(ApiError::PayloadTooLarge(
            "AI agent folder history reached its retention limit".to_string(),
        ));
    }
    Ok(())
}

fn retired_cutoff() -> String {
    (Utc::now() - Duration::days(RETIRED_DELEGATION_RETENTION_DAYS)).to_rfc3339()
}

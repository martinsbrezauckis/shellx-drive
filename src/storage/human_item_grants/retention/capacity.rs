use rusqlite::{params, OptionalExtension, Transaction};

use crate::error::{ApiError, ApiResult};

use super::{
    MAX_CURRENT_HUMAN_ITEM_GRANTS, MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_PRINCIPAL,
    MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_ROOT, MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_WORKSPACE,
};

pub(in crate::storage::human_item_grants) fn ensure_current_grant_capacity_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
    root_file_id: &str,
    principal_kind: &str,
    principal_ref: Option<&str>,
    now: &str,
) -> ApiResult<()> {
    let current_at_root: i64 = tx.query_row(
        "SELECT COUNT(*) FROM human_item_grants
         WHERE root_file_id = ?1 AND publication_pending = 0
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR julianday(expires_at) > julianday(?2))",
        params![root_file_id, now],
        |row| row.get(0),
    )?;
    if current_at_root >= MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_ROOT {
        return Err(ApiError::PayloadTooLarge(format!(
            "item sharing is limited to {MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_ROOT} current grants per root"
        )));
    }

    let current_for_principal: i64 = tx.query_row(
        "SELECT COUNT(*) FROM human_item_grants
         WHERE principal_kind = ?1
           AND COALESCE(principal_ref, '') = COALESCE(?2, '')
           AND publication_pending = 0 AND revoked_at IS NULL
           AND (expires_at IS NULL OR julianday(expires_at) > julianday(?3))",
        params![principal_kind, principal_ref, now],
        |row| row.get(0),
    )?;
    if current_for_principal >= MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_PRINCIPAL {
        return Err(ApiError::PayloadTooLarge(format!(
            "item sharing is limited to {MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_PRINCIPAL} current grants per principal"
        )));
    }

    let current_in_workspace: i64 = tx.query_row(
        "SELECT COUNT(*) FROM human_item_grants
         WHERE workspace_id = ?1 AND publication_pending = 0
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR julianday(expires_at) > julianday(?2))",
        params![workspace_id, now],
        |row| row.get(0),
    )?;
    if current_in_workspace >= MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_WORKSPACE {
        return Err(ApiError::PayloadTooLarge(format!(
            "item sharing is limited to {MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_WORKSPACE} current grants per workspace"
        )));
    }
    let global_sentinel: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM human_item_grants
             WHERE publication_pending = 0 AND revoked_at IS NULL
               AND (expires_at IS NULL OR julianday(expires_at) > julianday(?1))
             LIMIT 1 OFFSET ?2",
            params![now, MAX_CURRENT_HUMAN_ITEM_GRANTS - 1],
            |row| row.get(0),
        )
        .optional()?;
    if global_sentinel.is_some() {
        return Err(ApiError::PayloadTooLarge(format!(
            "item sharing is limited to {MAX_CURRENT_HUMAN_ITEM_GRANTS} current grants"
        )));
    }
    Ok(())
}

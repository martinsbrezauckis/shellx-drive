use chrono::Utc;
use rusqlite::{params, Transaction};

use crate::error::ApiResult;

mod capacity;

pub(super) use capacity::ensure_current_grant_capacity_in_tx;

pub(super) const MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_ROOT: i64 = 100;
pub(super) const MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_PRINCIPAL: i64 = 1_000;
pub(super) const MAX_CURRENT_HUMAN_ITEM_GRANTS_PER_WORKSPACE: i64 = 1_000;
pub(super) const MAX_CURRENT_HUMAN_ITEM_GRANTS: i64 = 10_000;
pub(super) const MAX_RETAINED_HUMAN_ITEM_GRANTS_PER_WORKSPACE: i64 = 1_000;

/// Convert elapsed grants into explicit revocations and keep only the newest
/// bounded terminal history in each workspace. Live and pending publications
/// are never removed.
pub(super) fn retire_expired_grants_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE human_item_grants
         SET revoked_at = COALESCE(revoked_at, expires_at), updated_at = ?1
         WHERE revoked_at IS NULL AND publication_pending = 0
           AND expires_at IS NOT NULL AND julianday(expires_at) <= julianday(?1)",
        [&now],
    )?;
    tx.execute(
        "DELETE FROM human_item_grants WHERE id IN (
             SELECT id FROM (
                 SELECT id,
                        ROW_NUMBER() OVER (
                            PARTITION BY workspace_id
                            ORDER BY updated_at DESC, id DESC
                        ) AS retained_position
                 FROM human_item_grants
                 WHERE revoked_at IS NOT NULL AND publication_pending = 0
             ) WHERE retained_position > ?1
         )",
        [MAX_RETAINED_HUMAN_ITEM_GRANTS_PER_WORKSPACE],
    )?;
    Ok(())
}

pub(super) fn prune_retained_grant_history_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
) -> ApiResult<()> {
    tx.execute(
        "DELETE FROM human_item_grants WHERE id IN (
             SELECT id FROM human_item_grants
             WHERE workspace_id = ?1 AND publication_pending = 0
               AND revoked_at IS NOT NULL
             ORDER BY updated_at DESC, id DESC
             LIMIT -1 OFFSET ?2
         )",
        params![workspace_id, MAX_RETAINED_HUMAN_ITEM_GRANTS_PER_WORKSPACE],
    )?;
    Ok(())
}

pub(super) fn retire_expired_grants_for_workspace_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE human_item_grants
         SET revoked_at = COALESCE(revoked_at, expires_at), updated_at = ?1
         WHERE workspace_id = ?2 AND revoked_at IS NULL AND publication_pending = 0
           AND expires_at IS NOT NULL AND julianday(expires_at) <= julianday(?1)",
        params![now, workspace_id],
    )?;
    prune_retained_grant_history_in_tx(tx, workspace_id)
}

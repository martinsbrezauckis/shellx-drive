//! Enrollment bounds all retained rows, so retirement and parent revocation
//! never need an admission slot. Expired, terminal history is reusable.

use rusqlite::{params, Transaction};

use crate::error::ApiResult;

const MAX_RETAINED_DEVICES_PER_OWNER: i64 = 64;
const MAX_HISTORY_PRUNE_BATCH: i64 = 64;

/// The caller commits bounded pruning even on rejected enrollment, allowing
/// legacy owners to retry without one unbounded delete transaction.
pub(super) fn admit_device_history_in_tx(
    tx: &Transaction<'_>,
    owner_account_id: &str,
    now: &str,
) -> ApiResult<bool> {
    let retained = retained_count(tx, owner_account_id)?;
    let prune = (retained - MAX_RETAINED_DEVICES_PER_OWNER + 1).clamp(0, MAX_HISTORY_PRUNE_BATCH);
    if prune > 0 {
        tx.execute(
            "DELETE FROM desktop_agent_devices WHERE id IN (
                 SELECT d.id FROM desktop_agent_devices d
                 WHERE d.owner_account_id = ?1 AND d.state IN ('retired', 'revoked')
                   AND NOT EXISTS (
                       SELECT 1 FROM desktop_agent_commands c WHERE c.device_id = d.id
                         AND c.status IN ('queued', 'leased', 'acknowledged', 'running',
                                          'relaunch_pending', 'cancel_requested')
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM desktop_agent_disconnect_completions c
                       WHERE c.device_id = d.id AND julianday(c.expires_at) > julianday(?2)
                   )
                 ORDER BY d.created_at ASC, d.id ASC LIMIT ?3
             )",
            params![owner_account_id, now, prune],
        )?;
    }
    Ok(retained_count(tx, owner_account_id)? < MAX_RETAINED_DEVICES_PER_OWNER)
}

fn retained_count(tx: &Transaction<'_>, owner_account_id: &str) -> ApiResult<i64> {
    Ok(tx.query_row(
        "SELECT COUNT(*) FROM desktop_agent_devices WHERE owner_account_id = ?1",
        [owner_account_id],
        |row| row.get(0),
    )?)
}

use rusqlite::Transaction;

use crate::error::ApiResult;

/// External SSO parent bindings are operational session state. Archives retain
/// their inert delegated records but never revive a parent-session edge.
pub(super) fn purge_sso_parent_bindings_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    tx.execute("DELETE FROM delegated_agent_parent_sessions", [])?;
    Ok(())
}

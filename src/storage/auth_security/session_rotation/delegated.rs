use rusqlite::params;

use crate::error::ApiResult;

pub(super) fn revoke_in_tx(
    tx: &rusqlite::Transaction<'_>,
    token_id: &str,
    email: &str,
    revoked_at: &str,
) -> ApiResult<()> {
    tx.execute(
        "UPDATE agent_tokens SET revoked_at = COALESCE(revoked_at, ?2)
         WHERE id = ?1 AND delegation_kind = 'delegated'",
        params![token_id, revoked_at],
    )?;
    tx.execute(
        "UPDATE office_edit_sessions SET used_at = COALESCE(used_at, ?2)
         WHERE source_credential_kind = 'delegated_agent'
           AND source_credential_id = ?1 AND actor_email = ?3
           AND used_at IS NULL",
        params![token_id, revoked_at, email],
    )?;
    Ok(())
}

//! Transactional account-security proof consumption and authority invalidation.

mod factor_consumption;
mod session_rotation;

use rusqlite::params;

use crate::error::ApiResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VerifiedLocalSecondFactor {
    NotRequired,
    TotpCounter(i64),
    RecoveryCode(String),
}

pub(super) use factor_consumption::{
    consume_current_second_factor_in_tx, consume_recovery_code_in_tx, consume_totp_counter_in_tx,
    totp_counter_for_enable,
};
pub(crate) use session_rotation::{AuthSessionReplacement, AuthSessionRotation};

/// Revoke authority derived from the actor's previous security state.
pub(super) fn revoke_actor_credentials_in_tx(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    revoked_at: &str,
) -> ApiResult<()> {
    revoke_sessions_and_office_in_tx(tx, email, revoked_at)?;
    tx.execute(
        "UPDATE app_tokens
         SET revoked_at = COALESCE(revoked_at, ?2)
         WHERE actor_email = ?1",
        params![email, revoked_at],
    )?;
    tx.execute(
        "UPDATE agent_principals
         SET disabled_at = COALESCE(disabled_at, ?2)
         WHERE created_by = ?1 AND creator_authority_kind = 'user'",
        params![email, revoked_at],
    )?;
    tx.execute(
        "UPDATE agent_tokens
         SET revoked_at = COALESCE(revoked_at, ?2)
         WHERE principal_id IN (
             SELECT id FROM agent_principals
             WHERE created_by = ?1 AND creator_authority_kind = 'user'
         )",
        params![email, revoked_at],
    )?;
    tx.execute(
        "UPDATE agent_folder_grants
         SET revoked_at = COALESCE(revoked_at, ?2)
         WHERE principal_id IN (
             SELECT id FROM agent_principals
             WHERE created_by = ?1 AND creator_authority_kind = 'user'
         )",
        params![email, revoked_at],
    )?;
    Ok(())
}

fn revoke_sessions_and_office_in_tx(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    revoked_at: &str,
) -> ApiResult<()> {
    tx.execute(
        "UPDATE auth_sessions
         SET revoked_at = COALESCE(revoked_at, ?2)
         WHERE actor_email = ?1",
        params![email, revoked_at],
    )?;
    tx.execute(
        "UPDATE office_edit_sessions
         SET used_at = COALESCE(used_at, ?2)
         WHERE actor_email = ?1 AND used_at IS NULL",
        params![email, revoked_at],
    )?;
    Ok(())
}

pub(super) fn rotate_prior_security_state_in_tx(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    revoked_at: &str,
    rotation: &AuthSessionRotation<'_>,
) -> ApiResult<()> {
    session_rotation::rotate_in_tx(tx, email, revoked_at, rotation)
}

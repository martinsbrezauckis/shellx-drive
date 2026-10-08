use rusqlite::params;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::AuthSession,
    storage::auth_sessions,
};

mod delegated;
#[derive(Clone, Debug)]
pub(crate) struct AuthSessionReplacement {
    pub session: AuthSession,
    pub token_hash: String,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}

pub(crate) struct AuthSessionRotation<'a> {
    pub actor: &'a Actor,
    pub source_credential: &'a DriveCredential,
    pub replacement: Option<&'a AuthSessionReplacement>,
}

pub(super) fn rotate_in_tx(
    tx: &rusqlite::Transaction<'_>,
    email: &str,
    revoked_at: &str,
    rotation: &AuthSessionRotation<'_>,
) -> ApiResult<()> {
    match (rotation.source_credential, rotation.replacement) {
        (DriveCredential::UserSession(source_session_id), Some(replacement)) => {
            if replacement.session.id == *source_session_id
                || replacement.session.actor_email != email
                || replacement.session.revoked
                || replacement.session.revoked_at.is_some()
            {
                return Err(ApiError::Validation(
                    "invalid replacement authentication session".to_string(),
                ));
            }
            tx.execute(
                "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, ?2)
                 WHERE actor_email = ?1",
                params![email, revoked_at],
            )?;
            tx.execute(
                "UPDATE office_edit_sessions SET used_at = COALESCE(used_at, ?2)
                 WHERE actor_email = ?1 AND used_at IS NULL",
                params![email, revoked_at],
            )?;
            auth_sessions::insert_auth_session_with_client_in_tx(
                tx,
                &replacement.session,
                &replacement.token_hash,
                replacement.client_ip.as_deref(),
                replacement.user_agent.as_deref(),
            )
        }
        (DriveCredential::DelegatedAgentToken(token_id), None) => {
            delegated::revoke_in_tx(tx, token_id, email, revoked_at)
        }
        _ => Err(ApiError::Forbidden),
    }
}

//! Exact pending-session retirement before any local bearer is discarded.

use super::*;

#[path = "pending_session_retirement/direct_records.rs"]
mod direct_records;
#[path = "pending_session_retirement/stored.rs"]
mod stored;

pub(super) use direct_records::direct_retirement_records;
pub(super) use stored::{stored_session_credentials, StoredSessionCredential};

/// Retire pending sessions not already tied to a direct local logout. The
/// caller persists this confirmed progress before invalidating that local
/// bearer, so a retry never uses an already-invalid bearer as an authorizer.
pub(super) async fn retire_pending_remote_sessions(
    state: &mut DesktopState,
    credentials: &[StoredSessionCredential],
    preferred_authorizer: Option<&StoredSessionCredential>,
    candidate: Option<&RemoteSessionRecord>,
    direct_retirements: &[RemoteSessionRecord],
    include_active_session: bool,
) -> CoreResult<()> {
    state.prune_remote_sessions(Utc::now());
    if include_active_session {
        if let Some(active) = state.active_remote_session.take() {
            state.record_pending_remote_revocation(active, Utc::now());
        }
    }
    let mut attempts = Vec::new();
    for record in state.pending_remote_revocations.clone() {
        if !pending_record_requires_authorized_retirement(&record, candidate, direct_retirements) {
            continue;
        }
        let outcome = match select_pending_retirement_authorizer(
            &record,
            preferred_authorizer,
            credentials,
            |record, credential| {
                record.identity_matches(
                    &credential.identity.server_url,
                    &credential.identity.email,
                )
            },
        ) {
            Some(credential) => match DriveHttpClient::new(&credential.identity.server_url) {
                Ok(client) => client
                    .revoke_session(&credential.bearer_token, &record.session_id)
                    .await,
                Err(_) => Err(DesktopError::Credential(
                    "pending remote session retirement was not confirmed; credentials were kept for retry"
                        .to_string(),
                )),
            },
            None => Err(DesktopError::Credential(
                "pending remote session has no matching saved credential; credentials were kept for retry"
                    .to_string(),
            )),
        };
        attempts.push((record, outcome));
    }
    for record in confirm_pending_remote_retirements(attempts)? {
        state.remove_remote_session_record(&record);
    }
    Ok(())
}

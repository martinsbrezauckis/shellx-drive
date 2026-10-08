//! Exact pending-session retirement before any local bearer is discarded.

use super::*;

#[path = "pending_session_retirement/direct_records.rs"]
mod direct_records;
#[path = "pending_session_retirement/stored.rs"]
mod stored;

pub(super) use direct_records::direct_retirement_records;
pub(super) use stored::{owned_canonical_keys, owned_pending_slots};
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
    let mut attempts = Vec::new();
    let records = state
        .pending_remote_revocations
        .iter()
        .chain(state.pending_candidate_session.iter())
        .chain(
            state
                .active_remote_session
                .iter()
                .filter(|_| include_active_session),
        )
        .cloned()
        .collect::<Vec<_>>();
    for record in records {
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

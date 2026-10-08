//! Persist remote confirmation together with removal of its exact locators.

use std::future::Future;

use shellx_drive_desktop_core::{
    DesktopError, DesktopState, LogoutOutcome, RemoteSessionRecord, RemoteSessionRevocationOutcome,
    Result as CoreResult, StateStore,
};

use super::{direct_sessions, remove_direct_session_record, StoredCredential};

pub(super) async fn retire_stored_sessions<Revoke, RevokeFuture, Logout, LogoutFuture>(
    store: &StateStore,
    state: &mut DesktopState,
    stored: &[StoredCredential],
    revoke: Revoke,
    logout: Logout,
) -> CoreResult<()>
where
    Revoke: FnMut(&StoredCredential, &RemoteSessionRecord) -> RevokeFuture,
    RevokeFuture: Future<Output = CoreResult<RemoteSessionRevocationOutcome>>,
    Logout: FnMut(&StoredCredential) -> LogoutFuture,
    LogoutFuture: Future<Output = CoreResult<LogoutOutcome>>,
{
    retire_with_save(
        state,
        stored,
        |confirmed| store.save(confirmed),
        revoke,
        logout,
    )
    .await
}

async fn retire_with_save<Save, Revoke, RevokeFuture, Logout, LogoutFuture>(
    state: &mut DesktopState,
    stored: &[StoredCredential],
    mut save: Save,
    mut revoke: Revoke,
    mut logout: Logout,
) -> CoreResult<()>
where
    Save: FnMut(&DesktopState) -> CoreResult<()>,
    Revoke: FnMut(&StoredCredential, &RemoteSessionRecord) -> RevokeFuture,
    RevokeFuture: Future<Output = CoreResult<RemoteSessionRevocationOutcome>>,
    Logout: FnMut(&StoredCredential) -> LogoutFuture,
    LogoutFuture: Future<Output = CoreResult<LogoutOutcome>>,
{
    let direct = direct_sessions(state, stored);
    let records = state
        .pending_remote_revocations
        .iter()
        .chain(state.pending_candidate_session.iter())
        .chain(state.active_remote_session.iter())
        .cloned()
        .collect::<Vec<_>>();
    for record in records {
        if direct.contains(&record.session_id) {
            continue;
        }
        let actor = stored
            .iter()
            .find(|credential| {
                record.identity_matches(&credential.identity.server_url, &credential.identity.email)
            })
            .ok_or_else(|| {
                DesktopError::Credential(
                    "a saved remote session has no same-account retirement bearer; credentials were kept"
                        .into(),
                )
            })?;
        match revoke(actor, &record).await? {
            RemoteSessionRevocationOutcome::Revoked
            | RemoteSessionRevocationOutcome::AlreadyAbsent => {
                state.remove_remote_session_record(&record);
                save(state)?;
            }
        }
    }
    // Preserve acknowledged prior revocations, but retain the exact direct
    // locators until all logouts and their confirmation are saved together.
    // A later logout/save error can retry idempotent logout without authorizing
    // old-session revokes with an already-invalid canonical bearer.
    let mut retired = state.clone();
    for credential in stored {
        match logout(credential).await? {
            LogoutOutcome::Revoked | LogoutOutcome::AlreadyInvalid => {
                remove_direct_session_record(&mut retired, credential);
            }
        }
    }
    if retired.pending_candidate_session.is_some()
        || retired.active_remote_session.is_some()
        || !retired.pending_remote_revocations.is_empty()
    {
        return Err(DesktopError::Credential(
            "not every saved Drive session reached confirmed remote retirement; credentials were kept"
                .into(),
        ));
    }
    retired
        .pending_disconnect_cleanup_mut()
        .ok_or_else(|| DesktopError::InvalidState("disconnect cleanup intent disappeared".into()))?
        .confirm_remote_retirement();
    save(&retired)?;
    *state = retired;
    Ok(())
}

#[cfg(test)]
mod tests;

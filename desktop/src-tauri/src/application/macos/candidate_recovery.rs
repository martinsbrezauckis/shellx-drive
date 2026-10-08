//! Keychain pending-candidate publication and interrupted-login recovery.
//!
//! Bearers never enter durable state. A pending Keychain slot plus its
//! non-secret remote-session locator is persisted before canonical replacement.

mod cancellation;
mod isolation;
mod prior;
mod publication;

#[cfg(test)]
mod tests;

use shellx_drive_desktop_core::{
    CredentialStore, DesktopError, DisconnectRequest, DriveHttpClient, LogoutOutcome,
    PendingMacOsCredentialStore, RemoteSessionRecord, Result as CoreResult,
    CANDIDATE_RECOVERY_PAUSED_ERROR,
};

use super::*;
use crate::application::auth_publication::canceled_sign_in;
use crate::application::candidate_admission::prepare_candidate_state;
use crate::application::unix_candidate_recovery::{
    ordered_slots, persist_converged_candidate_state, recover_slot, RecoveryStores,
    RemoteRecoveryAction,
};
use crate::session_identity::SessionIdentity;
use cancellation::{refresh_pending, retire_staged_candidate, retire_unpublished_response};
use isolation::{
    begin_login_publication, owned_pending_keys, remove_exact, retire_prior_sessions, write_exact,
};
use prior::recover_prior_candidates;
pub(super) use publication::publish_authenticated_session;

pub(super) fn recover_at_startup(runtime: &Runtime) {
    let result = tauri::async_runtime::block_on(async {
        let _publication = runtime.auth_publication.lock().await;
        let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
        let mut state = runtime.coordinator.snapshot();
        let mut result = recover(runtime, &mut state).await;
        if result.is_ok() && state.clear_candidate_recovery_error() {
            if let Err(error) = runtime.store.save(&state) {
                result = Err(error);
            }
        }
        operation.finish_state(state);
        result
    });
    runtime.set_candidate_recovery_pending(result.is_err());
    if result.is_err() {
        runtime
            .coordinator
            .record_error(CANDIDATE_RECOVERY_PAUSED_ERROR);
        let _ = runtime.save();
    }
}

pub(super) fn require_login_identity(
    runtime: &Runtime,
    normalized_url: &str,
    email: &str,
) -> CoreResult<()> {
    if !runtime.candidate_recovery_pending() {
        return Ok(());
    }
    let requested = SessionIdentity::credential_key_for(normalized_url, email);
    let state_matches =
        shellx_drive_desktop_core::candidate_recovery_locator(&runtime.coordinator.snapshot())
            .is_some_and(|record| {
                SessionIdentity::credential_key_for(&record.server_url, &record.account_email)
                    == requested
            });
    let staged_matches = owned_pending_keys(&runtime.coordinator.snapshot())?
        .into_iter()
        .filter_map(|key| SessionIdentity::parse_pending_service_key(&key))
        .any(|slot| slot.identity.credential_key() == requested);
    let remembered = runtime
        .candidate_recovery_identities
        .lock()
        .expect("candidate recovery identity lock")
        .contains(&requested);
    if state_matches || staged_matches || remembered {
        Ok(())
    } else {
        Err(DesktopError::Credential(
            "Drive credential recovery permits sign-in only for its retained server and account"
                .to_string(),
        ))
    }
}

async fn recover(
    runtime: &Runtime,
    state: &mut shellx_drive_desktop_core::DesktopState,
) -> CoreResult<()> {
    let slots = owned_pending_keys(state)?;
    if slots.is_empty() && state.pending_candidate_session.is_none() {
        return Ok(());
    }
    for slot in ordered_slots(state, slots)? {
        let bearer = PendingMacOsCredentialStore
            .get(&slot.account_key)?
            .ok_or_else(candidate_error)?;
        let identity = &slot.identity;
        let bearer = bearer.as_str();
        if !runtime.owns_session_identity(identity) {
            let record = state
                .pending_candidate_session
                .iter()
                .chain(state.pending_remote_revocations.iter())
                .find(|record| {
                    record.session_id == slot.session_id
                        && record.identity_matches(&identity.server_url, &identity.email)
                })
                .cloned()
                .ok_or_else(candidate_error)?;
            let client = DriveHttpClient::new(&identity.server_url)?;
            retire_staged_candidate(runtime, state, &client, bearer, &record, &slot.account_key)
                .await?;
            continue;
        }
        recover_slot(
            state,
            &slot,
            bearer,
            RecoveryStores {
                canonical: runtime.platform.credentials(),
                pending: &PendingMacOsCredentialStore,
            },
            |persisted| runtime.store.save(persisted),
            |action| async move {
                match action {
                    RemoteRecoveryAction::RetireCandidate => {
                        DriveHttpClient::new(&identity.server_url)?
                            .logout(bearer)
                            .await
                            .map(|outcome| match outcome {
                                LogoutOutcome::Revoked | LogoutOutcome::AlreadyInvalid => (),
                            })
                            .map_err(|_| candidate_error())
                    }
                    RemoteRecoveryAction::RetirePriorCanonical => {
                        retire_prior_sessions(runtime, identity, bearer).await
                    }
                }
            },
            || Ok(()),
        )
        .await?;
    }
    if state.pending_candidate_session.is_some() {
        return Err(candidate_error());
    }
    Ok(())
}

fn candidate_error() -> DesktopError {
    DesktopError::Credential(
        "Drive credential recovery needs retry; credentials were kept for retry".to_string(),
    )
}

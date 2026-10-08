//! Startup reconciliation for Linux Secret Service candidate slots.

use shellx_drive_desktop_core::{
    CredentialStore, DesktopError, DriveHttpClient, LinuxCredentialStore, LogoutOutcome,
    PendingLinuxCredentialStore, Result as CoreResult, CANDIDATE_RECOVERY_PAUSED_ERROR,
};

use crate::application::unix_candidate_recovery::{
    ordered_slots, recover_slot, RecoveryStores, RemoteRecoveryAction,
};
use crate::{application::Runtime, session_identity::SessionIdentity};

pub(crate) fn recover_at_startup(runtime: &Runtime) {
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

async fn recover(
    runtime: &Runtime,
    state: &mut shellx_drive_desktop_core::DesktopState,
) -> CoreResult<()> {
    let slots = super::owned_pending_keys(state)?;
    if slots.is_empty() && state.pending_candidate_session.is_none() {
        return Ok(());
    }
    for slot in ordered_slots(state, slots)? {
        runtime.remember_candidate_recovery_identity(&slot.identity);
        let bearer = PendingLinuxCredentialStore
            .get(&slot.account_key)?
            .ok_or_else(candidate_error)?;
        let identity = &slot.identity;
        let bearer = bearer.as_str();
        // A failed duplicate setup may retain a candidate but owns no
        // canonical account credential. It can retire its candidate only.
        let owns_canonical = runtime.owns_session_identity(identity);
        if !owns_canonical {
            DriveHttpClient::new(&identity.server_url)?
                .logout(bearer)
                .await
                .map_err(|_| candidate_error())?;
            super::super::auth::cancellation::remove_retired_candidate(
                runtime,
                state,
                &slot.account_key,
            )?;
            continue;
        }
        recover_slot(
            state,
            &slot,
            bearer,
            RecoveryStores {
                canonical: &LinuxCredentialStore,
                pending: &PendingLinuxCredentialStore,
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
                        retire_prior_canonical_sessions(identity, bearer).await
                    }
                }
            },
            || Ok(()),
        )
        .await?;
    }
    state
        .pending_candidate_session
        .is_none()
        .then_some(())
        .ok_or_else(candidate_error)
}

async fn retire_prior_canonical_sessions(
    candidate: &SessionIdentity,
    candidate_bearer: &str,
) -> CoreResult<()> {
    if let Some(bearer) = LinuxCredentialStore.get(&candidate.credential_key())? {
        if bearer != candidate_bearer {
            DriveHttpClient::new(&candidate.server_url)?
                .logout(&bearer)
                .await
                .map_err(|_| candidate_error())?;
        }
    }
    Ok(())
}

fn candidate_error() -> DesktopError {
    DesktopError::Credential(
        "Drive credential recovery needs retry; credentials were kept for retry".to_string(),
    )
}

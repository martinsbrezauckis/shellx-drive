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
    let slots = PendingLinuxCredentialStore::service_account_keys()?;
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
            || LinuxCredentialStore::delete_service_credentials_except(&identity.credential_key()),
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
    for account_key in LinuxCredentialStore::service_account_keys()? {
        let Some(bearer) = LinuxCredentialStore.get(&account_key)? else {
            return Err(candidate_error());
        };
        let identity = SessionIdentity::parse_canonical_credential_key(&account_key)
            .ok_or_else(candidate_error)?;
        if identity.credential_key() == candidate.credential_key() && bearer == candidate_bearer {
            continue;
        }
        DriveHttpClient::new(&identity.server_url)?
            .logout(&bearer)
            .await
            .map_err(|_| candidate_error())?;
    }
    Ok(())
}

fn candidate_error() -> DesktopError {
    DesktopError::Credential(
        "Drive credential recovery needs retry; credentials were kept for retry".to_string(),
    )
}

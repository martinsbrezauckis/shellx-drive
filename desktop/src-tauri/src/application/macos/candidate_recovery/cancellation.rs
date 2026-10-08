//! Candidate retirement and latch refresh shared by macOS auth paths.

use chrono::Utc;
use shellx_drive_desktop_core::{
    classify_exact_credential_write, CredentialStore, DesktopError, DisconnectRequest,
    DriveHttpClient, ExactCredentialWrite, PendingMacOsCredentialStore, RemoteSessionRecord,
    Result as CoreResult,
};

use crate::{application::Runtime, session_identity::SessionIdentity};

/// Retire an authenticated response that lost its generation before candidate
/// staging. A logout error retains only an exact Keychain recovery pair; the
/// bearer is never written to canonical storage.
pub(super) async fn retire_unpublished_response(
    runtime: &Runtime,
    stopped: &mut DisconnectRequest,
    client: &DriveHttpClient,
    bearer_token: &str,
    record: &RemoteSessionRecord,
    pending_account_key: &str,
) -> CoreResult<()> {
    if client.logout(bearer_token).await.is_ok() {
        return Ok(());
    }

    runtime.remember_candidate_recovery_record(record);
    runtime.set_candidate_recovery_pending(true);
    let mut operation = super::begin_login_publication(stopped)?;
    let state = crate::application::candidate_admission::prepare_candidate_state(
        &runtime.coordinator.snapshot(),
        record,
        Utc::now(),
    )?;
    runtime.store.save(&state)?;
    operation.publish_persisted_state(state.clone())?;
    let pending = PendingMacOsCredentialStore;
    let result = match classify_exact_credential_write(
        pending.set(pending_account_key, bearer_token),
        pending.get(pending_account_key),
        bearer_token,
    ) {
        ExactCredentialWrite::Written => Ok(()),
        ExactCredentialWrite::NotWritten | ExactCredentialWrite::Unknown => {
            Err(DesktopError::Credential(
                "Drive canceled sign-in could not be staged for recovery.".to_string(),
            ))
        }
    };
    operation.finish_state(state);
    result
}

pub(super) async fn retire_staged_candidate(
    runtime: &Runtime,
    state: &mut shellx_drive_desktop_core::DesktopState,
    client: &DriveHttpClient,
    bearer_token: &str,
    record: &RemoteSessionRecord,
    pending_account_key: &str,
) -> CoreResult<()> {
    match client.logout(bearer_token).await {
        Ok(_) => {
            let slot =
                crate::session_identity::pending_credential_slot(state, pending_account_key)?;
            crate::application::unix_candidate_recovery::remove_retired_slot(
                state,
                &slot,
                &PendingMacOsCredentialStore,
                |persisted| runtime.store.save(persisted),
            )
        }
        Err(error) => {
            if state
                .active_remote_session
                .as_ref()
                .is_some_and(|active| active.same_remote_session(record))
                && state
                    .pending_candidate_session
                    .as_ref()
                    .is_none_or(|pending| pending.same_remote_session(record))
            {
                state.active_remote_session = None;
                state.pending_candidate_session = Some(record.clone());
            }
            runtime.store.save(state)?;
            Err(error)
        }
    }
}

pub(super) fn refresh_pending(runtime: &Runtime) {
    let state = runtime.coordinator.snapshot();
    if let Some(record) = state.pending_candidate_session.as_ref() {
        runtime.remember_candidate_recovery_record(record);
    }
    let pending = state.pending_candidate_session.is_some()
        || super::owned_pending_keys(&state)
            .map(|slots| {
                for key in &slots {
                    if let Some(slot) = SessionIdentity::parse_pending_service_key(key) {
                        runtime.remember_candidate_recovery_identity(&slot.identity);
                    }
                }
                !slots.is_empty()
            })
            .unwrap_or(true);
    runtime.set_candidate_recovery_pending(pending);
}

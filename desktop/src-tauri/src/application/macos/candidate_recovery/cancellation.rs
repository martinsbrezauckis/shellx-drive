//! Candidate retirement and latch refresh shared by macOS auth paths.

use chrono::Utc;
use shellx_drive_desktop_core::{
    classify_exact_credential_removal, classify_exact_credential_write, CredentialStore,
    DesktopError, DriveHttpClient, ExactCredentialRemoval, ExactCredentialWrite,
    PendingMacOsCredentialStore, RemoteSessionRecord, Result as CoreResult,
};

use crate::{application::Runtime, session_identity::SessionIdentity};

/// Retire an authenticated response that lost its generation before candidate
/// staging. A logout error retains only an exact Keychain recovery pair; the
/// bearer is never written to canonical storage.
pub(super) async fn retire_unpublished_response(
    runtime: &Runtime,
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
    runtime
        .coordinator
        .record_pending_candidate_session(record.clone(), Utc::now());
    runtime.save()?;
    let pending = PendingMacOsCredentialStore;
    match classify_exact_credential_write(
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
    }
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
            state.remove_remote_session_record(record);
            runtime.store.save(state)?;
            let pending = PendingMacOsCredentialStore;
            match classify_exact_credential_removal(
                pending.delete(pending_account_key),
                pending.get(pending_account_key),
            ) {
                ExactCredentialRemoval::Removed => Ok(()),
                ExactCredentialRemoval::Retained | ExactCredentialRemoval::Unknown => {
                    Err(DesktopError::Credential(
                        "Drive staged credential cleanup was not confirmed; recovery remains required."
                            .to_string(),
                    ))
                }
            }
        }
        Err(error) => {
            state.remove_remote_session_record(record);
            state.record_pending_candidate_session(record.clone(), Utc::now());
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
        || PendingMacOsCredentialStore::service_account_keys()
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

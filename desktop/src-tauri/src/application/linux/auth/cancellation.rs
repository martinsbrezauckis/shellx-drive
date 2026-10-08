//! Exact retirement for a candidate invalidated after Secret Service staging.

use chrono::Utc;
use shellx_drive_desktop_core::{
    classify_exact_credential_removal, classify_exact_credential_write, CredentialStore,
    DriveHttpClient, ExactCredentialRemoval, ExactCredentialWrite, PendingLinuxCredentialStore,
    RemoteSessionRecord, Result as CoreResult,
};

use crate::application::Runtime;

/// Retire an authenticated response that lost its generation before it could
/// stage a candidate. If the remote result is ambiguous, retain an exact,
/// non-canonical recovery pair for the same server/account/session instead.
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
    let pending = PendingLinuxCredentialStore;
    match classify_exact_credential_write(
        pending.set(pending_account_key, bearer_token),
        pending.get(pending_account_key),
        bearer_token,
    ) {
        ExactCredentialWrite::Written => Ok(()),
        ExactCredentialWrite::NotWritten | ExactCredentialWrite::Unknown => {
            Err(shellx_drive_desktop_core::DesktopError::Credential(
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
            // Persist server-confirmed retirement before deleting its exact
            // staged bearer. A persistence failure therefore leaves a
            // recoverable locator rather than an untracked secret.
            state.remove_remote_session_record(record);
            runtime.store.save(state)?;
            let pending = PendingLinuxCredentialStore;
            match classify_exact_credential_removal(
                pending.delete(pending_account_key),
                pending.get(pending_account_key),
            ) {
                ExactCredentialRemoval::Removed => Ok(()),
                ExactCredentialRemoval::Retained | ExactCredentialRemoval::Unknown => {
                    Err(shellx_drive_desktop_core::DesktopError::Credential(
                        "Drive staged credential cleanup was not confirmed; recovery remains required."
                            .to_string(),
                    ))
                }
            }
        }
        Err(error) => {
            // Keep the exact record and staged bearer for a later same-
            // identity recovery. It is never promoted to canonical storage.
            state.remove_remote_session_record(record);
            state.record_pending_candidate_session(record.clone(), Utc::now());
            runtime.store.save(state)?;
            Err(error)
        }
    }
}

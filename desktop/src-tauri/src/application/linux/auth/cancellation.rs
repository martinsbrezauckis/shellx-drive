//! Exact retirement for a candidate invalidated after Secret Service staging.

use chrono::Utc;
use shellx_drive_desktop_core::{
    classify_exact_credential_write, CredentialStore, DisconnectRequest, DriveHttpClient,
    ExactCredentialWrite, PendingLinuxCredentialStore, RemoteSessionRecord, Result as CoreResult,
};

use crate::application::Runtime;

/// Retire an authenticated response that lost its generation before it could
/// stage a candidate. If the remote result is ambiguous, retain an exact,
/// non-canonical recovery pair for the same server/account/session instead.
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
    let mut operation = stopped.try_begin()?.ok_or_else(|| {
        shellx_drive_desktop_core::DesktopError::InvalidState(
            "Drive synchronization has not stopped for sign-in recovery".to_string(),
        )
    })?;
    let state = crate::application::candidate_admission::prepare_candidate_state(
        &runtime.coordinator.snapshot(),
        record,
        Utc::now(),
    )?;
    runtime.store.save(&state)?;
    operation.publish_persisted_state(state.clone())?;
    let pending = PendingLinuxCredentialStore;
    let result = match classify_exact_credential_write(
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
        Ok(_) => remove_retired_candidate(runtime, state, pending_account_key),
        Err(error) => {
            // Keep the exact record and staged bearer for a later same-
            // identity recovery. It is never promoted to canonical storage.
            let mut retained = state.clone();
            retained.remove_remote_session_record(record);
            // This is the already-owned candidate, possibly now expired.
            // Demote it without pruning any other retained exact locators.
            retained.pending_candidate_session = Some(record.clone());
            *state = retained;
            runtime.store.save(state)?;
            Err(error)
        }
    }
}

/// Keep the durable exact locator while provider removal is uncertain. A
/// repeated remote retirement is harmless; an unowned retained bearer is not.
pub(in crate::application::linux) fn remove_retired_candidate(
    runtime: &Runtime,
    state: &mut shellx_drive_desktop_core::DesktopState,
    pending_account_key: &str,
) -> CoreResult<()> {
    let slot = crate::session_identity::pending_credential_slot(state, pending_account_key)?;
    crate::application::unix_candidate_recovery::remove_retired_slot(
        state,
        &slot,
        &PendingLinuxCredentialStore,
        |persisted| runtime.store.save(persisted),
    )
}

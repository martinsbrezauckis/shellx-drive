//! Local opt-in lifecycle for the outbound desktop-agent broker.
//!
//! The local-control module finishes durable credential enrollment before the
//! separate outbound poller can observe a remote command. It never accepts an
//! inbound connection.

use shellx_drive_desktop_core::{
    classify_exact_credential_removal, classify_exact_credential_write,
    desktop_agent_enrollment_fingerprint, CredentialStore, DesktopAgentDeviceAssertion,
    DesktopAgentObservedStatus, DesktopError, DriveHttpClient, ExactCredentialRemoval,
    ExactCredentialWrite, Result as CoreResult, CURRENT_DESKTOP_AGENT_PLATFORM,
};
use tauri::{AppHandle, State};

use super::{DesktopView, Runtime};

mod actions;
mod dispatcher;
mod poller;
#[cfg(test)]
#[path = "desktop_agent/tests.rs"]
mod tests;

pub(crate) use poller::{
    freeze_for_pending_disconnect, resume_agent_disconnect_completion,
    revoke_for_pending_disconnect, start_polling, stop_polling,
};

fn update_agent_state<T>(
    runtime: &Runtime,
    update: impl FnOnce(&mut shellx_drive_desktop_core::DesktopAgentControlState) -> CoreResult<T>,
) -> CoreResult<T> {
    runtime
        .coordinator
        .update_desktop_agent_control(update, |state| runtime.store.save(state))
}

/// Couple an agent-journal acknowledgement with another durable non-secret
/// record when only the broker may authorize its removal.
fn update_desktop_state<T>(
    runtime: &Runtime,
    update: impl FnOnce(&mut shellx_drive_desktop_core::DesktopState) -> CoreResult<T>,
) -> CoreResult<T> {
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let mut next = runtime.coordinator.snapshot();
    let value = update(&mut next)?;
    runtime.store.save(&next)?;
    operation.finish_state(next);
    Ok(value)
}

/// Resume a capability-authenticated Disconnect from the existing visible
/// Disconnect recovery action. It has no local path or token input and works
/// after the paired session was deliberately removed.
pub(crate) async fn retry_pending_disconnect_completion(
    app: &AppHandle,
    runtime: &Runtime,
) -> CoreResult<()> {
    dispatcher::resume_pending_disconnect_completion(runtime).await?;
    start_polling(app, runtime);
    Ok(())
}

pub(crate) fn pending_disconnect_requires_capability_retry(runtime: &Runtime) -> bool {
    runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .is_some_and(shellx_drive_desktop_core::DesktopAgentDisconnectContinuation::requires_capability_retry)
}

#[tauri::command]
pub(crate) async fn set_desktop_agent_control(
    app: AppHandle,
    runtime: State<'_, Runtime>,
    enabled: bool,
) -> Result<DesktopView, String> {
    if enabled {
        enable_after_local_confirmation(&runtime)
            .await
            .map_err(|error| error.to_string())?;
        start_polling(&app, &runtime);
    } else {
        disable_after_local_confirmation(&runtime)
            .await
            .map_err(|error| error.to_string())?;
        stop_polling(&runtime);
    }
    Ok(runtime.view())
}

/// The caller is the native Settings action. It is the only enrollment entry
/// point; no remote command can create a device registration or supply a
/// folder, server URL, password, TOTP code, or credential service key.
pub(crate) async fn enable_after_local_confirmation(runtime: &Runtime) -> CoreResult<()> {
    runtime.ensure_disconnect_cleanup_complete()?;
    runtime.require_candidate_recovery_complete()?;
    let _publication = runtime.auth_publication.lock().await;
    let state = runtime.coordinator.snapshot();
    let pair = state.pair.as_ref().ok_or(DesktopError::NeedsSetup)?;
    let enrollment_fingerprint =
        desktop_agent_enrollment_fingerprint(&pair.server_url, &pair.account_email);
    if state.desktop_agent_control.enabled {
        let active = state
            .desktop_agent_control
            .device_id
            .as_deref()
            .ok_or_else(|| {
                DesktopError::InvalidState("desktop-agent enrollment has no device ID".to_string())
            })?;
        if state.desktop_agent_control.pair_fingerprint.as_deref() == Some(&enrollment_fingerprint)
            && runtime
                .platform
                .desktop_agent_credentials()
                .get(active)?
                .is_some()
        {
            return Ok(());
        }
        return Err(DesktopError::InvalidState(
            "desktop-agent enrollment needs local disable and re-enrollment after its pair or credential changed".to_string(),
        ));
    }
    let session = runtime.current_session()?;
    let owner_bearer = runtime.current_token(&session)?;
    let client = DriveHttpClient::new(&session.server_url)?;
    let assertion = current_assertion(runtime, &enrollment_fingerprint)?;
    let registration = client
        .register_desktop_agent_device(&owner_bearer, CURRENT_DESKTOP_AGENT_PLATFORM, &assertion)
        .await?;
    let device_id = registration.device_id.clone();
    write_exact_agent_credential(
        runtime.platform.desktop_agent_credentials(),
        &device_id,
        &registration.device_credential,
    )?;

    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let mut next = runtime.coordinator.snapshot();
    if let Err(error) = next.desktop_agent_control.enroll(
        device_id.clone(),
        registration.credential_expires_at,
        enrollment_fingerprint,
    ) {
        let _ =
            remove_exact_agent_credential(runtime.platform.desktop_agent_credentials(), &device_id);
        return Err(error);
    }
    if let Err(error) = runtime.store.save(&next) {
        // Do not leave a secret in an unreferenced namespace. The server-side
        // registration has no local claimant once this delete succeeds.
        let _ = client
            .retire_desktop_agent_device(&device_id, &registration.device_credential, &assertion)
            .await;
        let _ =
            remove_exact_agent_credential(runtime.platform.desktop_agent_credentials(), &device_id);
        return Err(error);
    }
    operation.finish_state(next);
    Ok(())
}

/// Disable is also a local Settings action. The server must first retire the
/// exact device and reject unstarted commands; only then may local secret
/// deletion and state removal happen.
pub(crate) async fn disable_after_local_confirmation(runtime: &Runtime) -> CoreResult<()> {
    runtime.ensure_disconnect_cleanup_complete()?;
    let _publication = runtime.auth_publication.lock().await;
    let state = runtime.coordinator.snapshot();
    if !state.desktop_agent_control.enabled {
        return Ok(());
    }
    let device_id = state
        .desktop_agent_control
        .device_id
        .as_deref()
        .ok_or_else(|| {
            DesktopError::InvalidState("desktop-agent enrollment has no device ID".to_string())
        })?
        .to_string();
    let session = runtime.current_session()?;
    let owner_bearer = runtime.current_token(&session)?;
    let client = DriveHttpClient::new(&session.server_url)?;
    client
        .revoke_desktop_agent_device(&device_id, &owner_bearer)
        .await?;
    remove_exact_agent_credential(runtime.platform.desktop_agent_credentials(), &device_id)?;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let mut next = runtime.coordinator.snapshot();
    next.retire_desktop_agent_control();
    runtime.store.save(&next)?;
    operation.finish_state(next);
    Ok(())
}

pub(crate) fn current_assertion(
    runtime: &Runtime,
    pair_fingerprint: &str,
) -> CoreResult<DesktopAgentDeviceAssertion> {
    let state = runtime.coordinator.snapshot();
    Ok(DesktopAgentDeviceAssertion {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        pair_fingerprint: pair_fingerprint.to_string(),
        status: observed_status(runtime.status()),
        pending_disconnect_cleanup: state.has_pending_disconnect_cleanup(),
        candidate_recovery: runtime.candidate_recovery_pending(),
        last_terminal_command_id: state.desktop_agent_control.last_terminal_command_id,
    })
}

fn observed_status(status: shellx_drive_desktop_core::SyncStatus) -> DesktopAgentObservedStatus {
    use shellx_drive_desktop_core::SyncStatus;

    match status {
        SyncStatus::NeedsSetup => DesktopAgentObservedStatus::NeedsSetup,
        SyncStatus::Paused => DesktopAgentObservedStatus::Paused,
        SyncStatus::Synced | SyncStatus::Syncing | SyncStatus::NeedsReview => {
            DesktopAgentObservedStatus::Ready
        }
        SyncStatus::NeedsReconnect | SyncStatus::Offline | SyncStatus::Error => {
            DesktopAgentObservedStatus::Error
        }
    }
}

pub(crate) fn current_agent_assertion(
    runtime: &Runtime,
) -> CoreResult<DesktopAgentDeviceAssertion> {
    let state = runtime.coordinator.snapshot();
    let fingerprint = current_enrollment_fingerprint(&state)?;
    require_current_enrollment_binding(&state, &fingerprint)?;
    current_assertion(runtime, &fingerprint)
}

fn current_enrollment_fingerprint(
    state: &shellx_drive_desktop_core::DesktopState,
) -> CoreResult<String> {
    let pair = state.pair.as_ref().ok_or(DesktopError::NeedsSetup)?;
    Ok(desktop_agent_enrollment_fingerprint(
        &pair.server_url,
        &pair.account_email,
    ))
}

fn require_current_enrollment_binding(
    state: &shellx_drive_desktop_core::DesktopState,
    fingerprint: &str,
) -> CoreResult<()> {
    if state.desktop_agent_control.pair_fingerprint.as_deref() != Some(fingerprint) {
        return Err(DesktopError::InvalidState(
            "desktop-agent enrollment uses an earlier identity binding; disable and re-enroll locally"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn device_credential(runtime: &Runtime) -> CoreResult<(String, String)> {
    let state = runtime.coordinator.snapshot();
    if !state.desktop_agent_control.enabled {
        return Err(DesktopError::InvalidState(
            "desktop-agent control has not been enabled locally".to_string(),
        ));
    }
    let device_id = state.desktop_agent_control.device_id.ok_or_else(|| {
        DesktopError::InvalidState("desktop-agent enrollment has no device ID".to_string())
    })?;
    let credential = runtime
        .platform
        .desktop_agent_credentials()
        .get(&device_id)?
        .ok_or_else(|| {
            DesktopError::Credential("desktop-agent device credential is unavailable".to_string())
        })?;
    Ok((device_id, credential))
}

pub(super) fn write_exact_agent_credential(
    store: &dyn CredentialStore,
    device_id: &str,
    credential: &str,
) -> CoreResult<()> {
    match classify_exact_credential_write(
        store.set(device_id, credential),
        store.get(device_id),
        credential,
    ) {
        ExactCredentialWrite::Written => Ok(()),
        ExactCredentialWrite::NotWritten | ExactCredentialWrite::Unknown => {
            Err(DesktopError::Credential(
                "desktop-agent device credential could not be stored and read back exactly"
                    .to_string(),
            ))
        }
    }
}

pub(super) fn remove_exact_agent_credential(
    store: &dyn CredentialStore,
    device_id: &str,
) -> CoreResult<()> {
    match classify_exact_credential_removal(store.delete(device_id), store.get(device_id)) {
        ExactCredentialRemoval::Removed => Ok(()),
        ExactCredentialRemoval::Retained | ExactCredentialRemoval::Unknown => {
            Err(DesktopError::Credential(
                "desktop-agent device credential removal could not be verified".to_string(),
            ))
        }
    }
}

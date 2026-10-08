//! Local opt-in lifecycle for the outbound desktop-agent broker.
//!
//! The local-control module finishes durable credential enrollment before the
//! separate outbound poller can observe a remote command. It never accepts an
//! inbound connection.

use shellx_drive_desktop_core::{
    desktop_agent_enrollment_fingerprint, DesktopAgentDeviceAssertion, DesktopAgentObservedStatus,
    DesktopError, DriveHttpClient, Result as CoreResult, CURRENT_DESKTOP_AGENT_PLATFORM,
};
use tauri::{AppHandle, State};

use super::{ConnectionManager, DesktopView, Runtime};

mod actions;
mod credentials;
pub(crate) use credentials::{
    current_device_credential_key, device_credential, scoped_device_cleanup_slot,
};
pub(super) use credentials::{
    finish_confirmed_agent_retirement, publish_registered_agent, remove_exact_agent_credential,
    write_exact_agent_credential,
};
#[cfg(test)]
#[path = "desktop_agent/credential_tests.rs"]
mod credential_tests;
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
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    enabled: bool,
) -> Result<DesktopView, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(|error| error.to_string())?;
    manager
        .ensure_mutation_allowed()
        .map_err(|error| error.to_string())?;
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
    // Admit the complete enrollment before issuing a new remote device or
    // writing its credential. Sync, removal and updater restart reservation
    // must not reject publication after the side effects have already happened.
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let state = runtime.coordinator.snapshot();
    let pair = state.pair.as_ref().ok_or(DesktopError::NeedsSetup)?;
    let enrollment_fingerprint =
        desktop_agent_enrollment_fingerprint(&pair.server_url, &pair.account_email);
    if state.desktop_agent_control.enabled {
        let active = current_device_credential_key(&state)?;
        if state.desktop_agent_control.pair_fingerprint.as_deref() == Some(&enrollment_fingerprint)
            && runtime
                .platform
                .desktop_agent_credentials()
                .get(&active)?
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
    publish_registered_agent(
        runtime,
        &mut operation,
        &registration,
        enrollment_fingerprint,
        || {
            client.retire_desktop_agent_device(
                &registration.device_id,
                &registration.device_credential,
                &assertion,
            )
        },
    )
    .await
}

/// Disable is also a local Settings action. The server must first retire the
/// exact device and reject unstarted commands; only then may local secret
/// deletion and state removal happen.
pub(crate) async fn disable_after_local_confirmation(runtime: &Runtime) -> CoreResult<()> {
    runtime.ensure_disconnect_cleanup_complete()?;
    let _publication = runtime.auth_publication.lock().await;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
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
    current_device_credential_key(&state)?;
    let session = runtime.current_session()?;
    let owner_bearer = runtime.current_token(&session)?;
    let client = DriveHttpClient::new(&session.server_url)?;
    client
        .revoke_desktop_agent_device(&device_id, &owner_bearer)
        .await?;
    finish_confirmed_agent_retirement(runtime, &mut operation, &state)
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

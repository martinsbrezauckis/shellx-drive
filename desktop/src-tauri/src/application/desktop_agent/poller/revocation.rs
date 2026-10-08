//! Reconcile an externally revoked broker device without treating a generic
//! device-bearer failure as permission to clear local enrollment.

use shellx_drive_desktop_core::{
    CredentialStore, DesktopAgentControlState, DesktopError, DesktopState, DriveHttpClient,
    Result as CoreResult,
};

use super::super::{
    current_device_credential_key, remove_exact_agent_credential, update_desktop_state, Runtime,
};

/// The poller calls this only for an error returned by a device-bearer broker
/// operation. It uses the independently authenticated current owner session
/// to confirm that this exact persisted device is revoked before removing the
/// exact device credential and clearing its journal.
pub(super) async fn reconcile_external_device_revocation(
    runtime: &Runtime,
    device_bearer_error: &DesktopError,
) -> CoreResult<bool> {
    if !is_device_bearer_unauthorized(device_bearer_error) {
        return Ok(false);
    }

    let Some(device_id) = current_enrolled_device_id(runtime)? else {
        return Ok(false);
    };
    reconcile_confirmed_external_revocation(runtime, &device_id).await
}

/// Recover the narrow crash/save-failure window after exact credential
/// deletion. Absence only starts an owner-authenticated inquiry; it never by
/// itself authorizes clearing the broker enrollment.
pub(super) async fn reconcile_missing_device_credential(runtime: &Runtime) -> CoreResult<bool> {
    let Some(device_id) = current_missing_device_credential_id(runtime)? else {
        return Ok(false);
    };
    reconcile_confirmed_external_revocation(runtime, &device_id).await
}

async fn reconcile_confirmed_external_revocation(
    runtime: &Runtime,
    device_id: &str,
) -> CoreResult<bool> {
    let credential_key = current_device_credential_key(&runtime.coordinator.snapshot())?;
    let session = runtime.current_session()?;
    let owner_bearer = runtime.current_token(&session)?;
    let client = DriveHttpClient::new(&session.server_url)?;
    if !client
        .owner_confirms_desktop_agent_device_revoked(&owner_bearer, device_id)
        .await?
    {
        return Ok(false);
    }

    // Server confirmation is not enough by itself: do not clear durable
    // control state until the matching platform credential is absent too.
    remove_exact_agent_credential(
        runtime.platform.desktop_agent_credentials(),
        &credential_key,
    )?;
    update_desktop_state(runtime, |state| {
        Ok(clear_exact_current_device_after_confirmed_revocation(
            state, device_id, true,
        ))
    })
}

fn current_enrolled_device_id(runtime: &Runtime) -> CoreResult<Option<String>> {
    let state = runtime.coordinator.snapshot();
    if !state.desktop_agent_control.enabled {
        return Ok(None);
    }
    current_enrolled_device_id_for_control(&state.desktop_agent_control).map(Some)
}

fn current_missing_device_credential_id(runtime: &Runtime) -> CoreResult<Option<String>> {
    let state = runtime.coordinator.snapshot();
    if !state.desktop_agent_control.enabled {
        return Ok(None);
    }
    missing_device_credential_id(
        &state.desktop_agent_control,
        runtime.platform.desktop_agent_credentials(),
        &current_device_credential_key(&state)?,
    )
}

fn current_enrolled_device_id_for_control(
    control: &DesktopAgentControlState,
) -> CoreResult<String> {
    if !control.enabled {
        return Err(DesktopError::InvalidState(
            "desktop-agent external revocation reconciliation requires enabled control".to_string(),
        ));
    }
    control.device_id.clone().ok_or_else(|| {
        DesktopError::InvalidState(
            "enabled desktop-agent control has no device ID for revocation reconciliation"
                .to_string(),
        )
    })
}

fn missing_device_credential_id(
    control: &DesktopAgentControlState,
    store: &dyn CredentialStore,
    credential_key: &str,
) -> CoreResult<Option<String>> {
    if !control.enabled {
        return Ok(None);
    }
    let device_id = current_enrolled_device_id_for_control(control)?;
    shellx_drive_desktop_core::validate_desktop_agent_device_credential_key(credential_key)?;
    if control.credential_key.as_deref() != Some(credential_key) {
        return Err(DesktopError::Credential(
            "desktop-agent credential ownership recovery is pending".to_string(),
        ));
    }
    Ok(store.get(credential_key)?.is_none().then_some(device_id))
}

fn clear_exact_current_device_after_confirmed_revocation(
    state: &mut DesktopState,
    device_id: &str,
    owner_confirmed_revocation: bool,
) -> bool {
    if !owner_confirmed_revocation
        || !state.desktop_agent_control.enabled
        || state.desktop_agent_control.device_id.as_deref() != Some(device_id)
    {
        return false;
    }
    state.retire_desktop_agent_control();
    true
}

fn is_device_bearer_unauthorized(error: &DesktopError) -> bool {
    matches!(error, DesktopError::Server { status: 401, .. })
}

#[cfg(test)]
mod tests;

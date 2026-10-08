//! Connection-scoped device-secret publication, lookup and exact retirement.

use shellx_drive_desktop_core::{
    classify_exact_credential_removal, classify_exact_credential_write,
    desktop_agent_device_credential_key, validate_desktop_agent_device_credential_key,
    CredentialStore, DesktopAgentRegistration, DesktopError, DesktopState, ExactCredentialRemoval,
    ExactCredentialWrite, LifecycleOperation, Result as CoreResult,
};

use super::{current_enrollment_fingerprint, Runtime};

/// The storage/publication half of enrollment uses the same local authority
/// after registration. The caller retains its lifecycle reservation across
/// the broker request and any rollback retirement.
pub(crate) async fn publish_registered_agent<F, Fut>(
    runtime: &Runtime,
    operation: &mut LifecycleOperation,
    registration: &DesktopAgentRegistration,
    enrollment_fingerprint: String,
    retire_registration: F,
) -> CoreResult<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = CoreResult<()>>,
{
    registration.validate()?;
    if enrollment_fingerprint != current_enrollment_fingerprint(&runtime.coordinator.snapshot())? {
        return Err(DesktopError::InvalidState(
            "desktop-agent enrollment identity changed before credential publication".into(),
        ));
    }
    let device_id = registration.device_id.clone();
    let credential_key = desktop_agent_device_credential_key(&enrollment_fingerprint, &device_id)?;
    write_exact_agent_credential(
        runtime.platform.desktop_agent_credentials(),
        &credential_key,
        &registration.device_credential,
    )?;

    let mut next = runtime.coordinator.snapshot();
    if let Err(error) = next.desktop_agent_control.enroll(
        device_id.clone(),
        registration.credential_expires_at,
        enrollment_fingerprint,
    ) {
        let _ = remove_exact_agent_credential(
            runtime.platform.desktop_agent_credentials(),
            &credential_key,
        );
        return Err(error);
    }
    if let Err(error) = runtime.store.save(&next) {
        // Do not leave a secret in an unreferenced namespace. The server-side
        // registration has no local claimant once this delete succeeds.
        let _ = retire_registration().await;
        let _ = remove_exact_agent_credential(
            runtime.platform.desktop_agent_credentials(),
            &credential_key,
        );
        return Err(error);
    }
    operation.finish_state(next);
    Ok(())
}

pub(crate) fn finish_confirmed_agent_retirement(
    runtime: &Runtime,
    operation: &mut LifecycleOperation,
    state: &DesktopState,
) -> CoreResult<()> {
    let credential_key = current_device_credential_key(state)?;
    remove_exact_agent_credential(
        runtime.platform.desktop_agent_credentials(),
        &credential_key,
    )?;
    let mut next = state.clone();
    next.retire_desktop_agent_control();
    runtime.store.save(&next)?;
    operation.finish_state(next);
    Ok(())
}

pub(crate) fn device_credential(runtime: &Runtime) -> CoreResult<(String, String)> {
    let state = runtime.coordinator.snapshot();
    if !state.desktop_agent_control.enabled {
        return Err(DesktopError::InvalidState(
            "desktop-agent control has not been enabled locally".to_string(),
        ));
    }
    let credential_key = current_device_credential_key(&state)?;
    let device_id = state.desktop_agent_control.device_id.ok_or_else(|| {
        DesktopError::InvalidState("desktop-agent enrollment has no device ID".to_string())
    })?;
    let credential = runtime
        .platform
        .desktop_agent_credentials()
        .get(&credential_key)?
        .ok_or_else(|| {
            DesktopError::Credential("desktop-agent device credential is unavailable".to_string())
        })?;
    Ok((device_id, credential))
}

/// Compare the durable locator with the currently admitted local identity,
/// never with a credential-store key supplied by the remote registration.
pub(crate) fn current_device_credential_key(state: &DesktopState) -> CoreResult<String> {
    let control = &state.desktop_agent_control;
    let device_id = control.device_id.as_deref().ok_or_else(|| {
        DesktopError::InvalidState("desktop-agent enrollment has no device ID".to_string())
    })?;
    let expected =
        desktop_agent_device_credential_key(&current_enrollment_fingerprint(state)?, device_id)?;
    if control.credential_key.as_deref() != Some(&expected) {
        return Err(DesktopError::Credential(
            "Retained desktop-agent credential needs connection ownership recovery; its secret was kept. Reopen Drive after restoring the retained connection states."
                .to_string(),
        ));
    }
    Ok(expected)
}

pub(crate) fn scoped_device_cleanup_slot(
    state: &DesktopState,
) -> CoreResult<Option<shellx_drive_desktop_core::DisconnectCredentialSlot>> {
    if !state.desktop_agent_control.enabled {
        return Ok(None);
    }
    Ok(Some(shellx_drive_desktop_core::DisconnectCredentialSlot {
        namespace:
            shellx_drive_desktop_core::DisconnectCredentialNamespace::DesktopAgentDeviceScoped,
        account_key: current_device_credential_key(state)?,
    }))
}

pub(crate) fn write_exact_agent_credential(
    store: &dyn CredentialStore,
    credential_key: &str,
    credential: &str,
) -> CoreResult<()> {
    validate_desktop_agent_device_credential_key(credential_key)?;
    match classify_exact_credential_write(
        store.set(credential_key, credential),
        store.get(credential_key),
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

pub(crate) fn remove_exact_agent_credential(
    store: &dyn CredentialStore,
    credential_key: &str,
) -> CoreResult<()> {
    validate_desktop_agent_device_credential_key(credential_key)?;
    match classify_exact_credential_removal(store.delete(credential_key), store.get(credential_key))
    {
        ExactCredentialRemoval::Removed => Ok(()),
        ExactCredentialRemoval::Retained | ExactCredentialRemoval::Unknown => {
            Err(DesktopError::Credential(
                "desktop-agent device credential removal could not be verified".to_string(),
            ))
        }
    }
}

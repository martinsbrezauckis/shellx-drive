//! Reconcile an externally revoked broker device without treating a generic
//! device-bearer failure as permission to clear local enrollment.

use shellx_drive_desktop_core::{
    CredentialStore, DesktopAgentControlState, DesktopError, DesktopState, DriveHttpClient,
    Result as CoreResult,
};

use super::super::{remove_exact_agent_credential, update_desktop_state, Runtime};

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
    remove_exact_agent_credential(runtime.platform.desktop_agent_credentials(), device_id)?;
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
    missing_device_credential_id(
        &state.desktop_agent_control,
        runtime.platform.desktop_agent_credentials(),
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
) -> CoreResult<Option<String>> {
    if !control.enabled {
        return Ok(None);
    }
    let device_id = current_enrolled_device_id_for_control(control)?;
    Ok(store.get(&device_id)?.is_none().then_some(device_id))
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
mod tests {
    use shellx_drive_desktop_core::{
        CredentialStore, DesktopError, DesktopState, FakeCredentialStore,
    };

    use super::{
        clear_exact_current_device_after_confirmed_revocation, is_device_bearer_unauthorized,
        missing_device_credential_id,
    };

    #[test]
    fn only_a_device_bearer_unauthorized_response_starts_reconciliation() {
        assert!(is_device_bearer_unauthorized(&DesktopError::Server {
            status: 401,
            message: "sign-in was not accepted".to_string(),
        }));
        assert!(!is_device_bearer_unauthorized(&DesktopError::Server {
            status: 403,
            message: "the account cannot access this Drive location".to_string(),
        }));
        assert!(!is_device_bearer_unauthorized(&DesktopError::Server {
            status: 409,
            message: "Drive changed this item before the update could be applied".to_string(),
        }));
    }

    #[test]
    fn missing_credential_after_an_unsaved_clear_retries_only_when_revocation_is_confirmed() {
        let store = FakeCredentialStore::default();
        let mut persisted = DesktopState::default();
        persisted
            .desktop_agent_control
            .enroll("device_current".to_string(), None, "a".repeat(64))
            .unwrap();
        persisted
            .record_desktop_update_restart_for_agent(
                "1.2.3".to_string(),
                "candidate_current".to_string(),
                "command_current".to_string(),
            )
            .unwrap();
        store.set("device_current", "sxd_device_fixture").unwrap();
        store.delete("device_current").unwrap();

        // This models the post-delete state-save failure/crash: the secret is
        // gone but the last durable state is still enabled on the next start.
        assert_eq!(
            missing_device_credential_id(&persisted.desktop_agent_control, &store).unwrap(),
            Some("device_current".to_string())
        );
        let mut unsaved_attempt = persisted.clone();
        assert!(clear_exact_current_device_after_confirmed_revocation(
            &mut unsaved_attempt,
            "device_current",
            true
        ));
        assert!(persisted.desktop_agent_control.enabled);
        assert!(persisted.pending_desktop_update_restart.is_some());

        assert!(!clear_exact_current_device_after_confirmed_revocation(
            &mut persisted,
            "device_other",
            true
        ));
        assert!(persisted.pending_desktop_update_restart.is_some());

        // A missing credential with a live/other server readback is not a
        // revocation confirmation and must retain the durable enrollment.
        assert!(!clear_exact_current_device_after_confirmed_revocation(
            &mut persisted,
            "device_current",
            false
        ));
        assert_eq!(
            persisted.desktop_agent_control.device_id.as_deref(),
            Some("device_current")
        );
        assert!(persisted.pending_desktop_update_restart.is_some());

        assert!(clear_exact_current_device_after_confirmed_revocation(
            &mut persisted,
            "device_current",
            true
        ));
        assert!(!persisted.desktop_agent_control.enabled);
        assert!(persisted.desktop_agent_control.device_id.is_none());
        assert!(persisted.desktop_agent_control.command_journal.is_empty());
        assert!(persisted.pending_desktop_update_restart.is_none());
    }
}

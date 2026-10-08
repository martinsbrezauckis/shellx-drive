//! Fail-closed macOS Disconnect flow.
//! Remote logout is confirmed before Keychain, marker, or LaunchAgent cleanup.
//! The selected local Drive folders are intentionally retained.

use chrono::Utc;
use shellx_drive_desktop_core::{
    DesktopState, DisconnectCleanupIntent, MacOsCredentialStore, StateStore,
};
use tauri::State;

use super::*;

#[tauri::command]
pub(super) async fn disconnect(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
) -> Result<DesktopView, String> {
    disconnect_impl(&app, &runtime).await
}

pub(crate) async fn disconnect_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
) -> Result<DesktopView, String> {
    if crate::application::desktop_agent::pending_disconnect_requires_capability_retry(runtime) {
        return crate::application::desktop_agent::retry_pending_disconnect_completion(
            app, runtime,
        )
        .await
        .map(|_| runtime.view())
        .map_err(macos_error);
    }
    let _offboarding = runtime
        .auth_offboarding
        .begin_offboarding()
        .map_err(macos_error)?;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    let mut disconnect = crate::application::request_disconnect_after_sync(runtime)
        .await
        .map_err(macos_error)?;
    let _publication = runtime.auth_publication.lock().await;
    let mut operation = disconnect
        .try_begin()
        .map_err(macos_error)?
        .ok_or_else(|| {
            macos_error(DesktopError::InvalidState(
                "synchronization restarted while Disconnect was pending".to_string(),
            ))
        })?;
    let mut state = runtime.coordinator.snapshot();
    if !state.has_pending_disconnect_cleanup() {
        let intent = DisconnectCleanupIntent::for_disconnect_pairs(
            state.pairs().cloned().collect(),
            MacOsCredentialStore::disconnect_credential_slots().map_err(macos_error)?,
        )
        .map_err(macos_error)?;
        state
            .begin_disconnect_cleanup(intent)
            .map_err(macos_error)?;
        runtime.store.save(&state).map_err(macos_error)?;
        operation
            .publish_persisted_state(state.clone())
            .map_err(macos_error)?;
    }
    let remote_retirement_confirmed = state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed);
    if !remote_retirement_confirmed {
        if let Err(error) =
            crate::application::desktop_agent::freeze_for_pending_disconnect(runtime).await
        {
            operation.finish_state(state);
            shell::update_tray(app, runtime);
            return Err(macos_error(error));
        }
    }
    sync::stop_polling(runtime);

    let local_cleanup_only = state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
        && state.pair.is_none();
    if !local_cleanup_only {
        if let Err(error) = crate::application::unix_uninstall::remote::retire_remote_credentials(
            &runtime.store,
            &mut state,
        )
        .await
        {
            operation.finish_state(state);
            shell::update_tray(app, runtime);
            return Err(macos_error(error));
        }
        state
            .pending_disconnect_cleanup_mut()
            .ok_or_else(|| "Disconnect cleanup state was lost before local cleanup.".to_string())?
            .confirm_remote_retirement();
        state = state.into_disconnected(Utc::now());
        runtime.store.save(&state).map_err(macos_error)?;
        operation
            .publish_persisted_state(state.clone())
            .map_err(macos_error)?;
        *runtime.session.lock().expect("session lock") = None;
    }

    complete_local_cleanup(&runtime.store, &mut state).map_err(macos_error)?;
    operation.finish_state(state);
    *runtime.session.lock().expect("session lock") = None;
    invalidate_pending_confirmation(runtime);
    shell::update_tray(app, runtime);
    Ok(runtime.view())
}

pub(crate) fn complete_local_cleanup(
    store: &StateStore,
    state: &mut DesktopState,
) -> CoreResult<()> {
    complete_local_cleanup_with_finalizer(store, state, DesktopState::finish_disconnect_cleanup)
}

pub(crate) fn complete_local_cleanup_with_finalizer(
    store: &StateStore,
    state: &mut DesktopState,
    finalize: impl FnOnce(&mut DesktopState) -> CoreResult<()>,
) -> CoreResult<()> {
    if !state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
    {
        return Err(DesktopError::InvalidState(
            "local Disconnect cleanup cannot run before remote retirement is confirmed".to_string(),
        ));
    }
    while let Some(marker) = state
        .pending_disconnect_cleanup()
        .and_then(|cleanup| cleanup.marker.clone())
    {
        let expected = marker.marker.local_root_identity.as_ref().ok_or_else(|| {
            DesktopError::InvalidState(
                "Disconnect marker has no macOS root identity; local files were left untouched"
                    .to_string(),
            )
        })?;
        let guard = crate::platform::unix::filesystem::UnixRootGuard::acquire(
            &marker.local_root,
            Some(expected),
        )?;
        guard.remove_exact_pair_marker(&marker.marker)?;
        let mut next = state.clone();
        next.pending_disconnect_cleanup_mut()
            .expect("cleanup remains present")
            .acknowledge_marker();
        store.save(&next)?;
        *state = next;
    }
    while let Some(slot) = state
        .pending_disconnect_cleanup()
        .and_then(|cleanup| cleanup.next_credential_slot().cloned())
    {
        MacOsCredentialStore::delete_and_verify_disconnect_credential_slot(&slot)?;
        let mut next = state.clone();
        next.pending_disconnect_cleanup_mut()
            .expect("cleanup remains present")
            .acknowledge_credential_slot(&slot)?;
        store.save(&next)?;
        *state = next;
    }
    crate::platform::unix::remove_owned_launch_at_login()?;
    let mut next = state.clone();
    next.launch_at_login = false;
    finalize(&mut next)?;
    store.save(&next)?;
    *state = next;
    Ok(())
}

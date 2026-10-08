//! Linux Disconnect retirement and exact local cleanup.

use chrono::Utc;
use shellx_drive_desktop_core::{
    DesktopError, DesktopState, DisconnectCleanupIntent, DisconnectCredentialSlot,
    LinuxCredentialStore, Result as CoreResult, StateStore,
};
use tauri::{AppHandle, State};

use crate::{
    application::{invalidate_pending_confirmation, DesktopView, Runtime},
    platform::unix::filesystem::UnixRootGuard,
};

use super::{shell::update_tray, sync};

const CLEANUP_PENDING: &str =
    "Disconnect local cleanup remains pending; retry Disconnect to complete it.";

/// Startup may resume only a cleanup whose remote retirement was durably
/// confirmed and whose paired state was already cleared.
pub(super) fn resume_linux_disconnect_cleanup(
    store: &StateStore,
    state: &mut DesktopState,
) -> CoreResult<()> {
    if state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
        && state.pair.is_none()
    {
        crate::platform::unix::remove_owned_launch_at_login()?;
        complete_local_cleanup(store, state)?;
    }
    Ok(())
}

#[tauri::command]
pub(super) async fn disconnect(
    app: AppHandle,
    runtime: State<'_, Runtime>,
) -> Result<DesktopView, String> {
    disconnect_impl(&app, &runtime).await
}

pub(crate) async fn disconnect_impl(
    app: &AppHandle,
    runtime: &Runtime,
) -> Result<DesktopView, String> {
    if crate::application::desktop_agent::pending_disconnect_requires_capability_retry(runtime) {
        return crate::application::desktop_agent::retry_pending_disconnect_completion(
            app, runtime,
        )
        .await
        .map(|_| runtime.view())
        .map_err(present_error);
    }
    let _offboarding = runtime
        .auth_offboarding
        .begin_offboarding()
        .map_err(present_error)?;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    let mut disconnect = crate::application::request_disconnect_after_sync(runtime)
        .await
        .map_err(present_error)?;
    let _publication = runtime.auth_publication.lock().await;
    let mut operation = disconnect
        .try_begin()
        .map_err(present_error)?
        .ok_or_else(|| {
            present_error(DesktopError::InvalidState(
                "synchronization restarted while Disconnect was pending".to_string(),
            ))
        })?;
    let mut state = runtime.coordinator.snapshot();
    persist_intent(runtime, &mut state).map_err(present_error)?;
    operation
        .publish_persisted_state(state.clone())
        .map_err(present_error)?;
    let remote_retirement_confirmed = state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed);
    if !remote_retirement_confirmed {
        if let Err(error) =
            crate::application::desktop_agent::freeze_for_pending_disconnect(runtime).await
        {
            operation.finish_state(state);
            update_tray(app, runtime);
            return Err(present_error(error));
        }
    }
    sync::stop_polling(runtime);

    let local_only = state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
        && state.pair.is_none();
    if !local_only {
        if let Err(error) = crate::application::unix_uninstall::remote::retire_remote_credentials(
            &runtime.store,
            &mut state,
        )
        .await
        {
            operation.finish_state(state);
            update_tray(app, runtime);
            return Err(present_error(error));
        }
        let mut disconnected = state.clone();
        disconnected
            .pending_disconnect_cleanup_mut()
            .ok_or_else(|| {
                present_error(DesktopError::InvalidState(
                    "disconnect cleanup intent disappeared".to_string(),
                ))
            })?
            .confirm_remote_retirement();
        disconnected = disconnected.into_disconnected(Utc::now());
        disconnected.launch_at_login = false;
        runtime.store.save(&disconnected).map_err(present_error)?;
        operation
            .publish_persisted_state(disconnected.clone())
            .map_err(present_error)?;
        state = disconnected;
        *runtime.session.lock().expect("session lock") = None;
        invalidate_pending_confirmation(runtime);
    }
    if let Err(error) = runtime.platform.set_launch_at_login(false) {
        state.last_error = Some(format!(
            "Disconnect retired remote access but Linux autostart cleanup needs retry: {error}"
        ));
        let _ = runtime.store.save(&state);
        operation.finish_state(state);
        update_tray(app, runtime);
        return Err(present_error(error));
    }
    if let Err(error) = complete_local_cleanup(&runtime.store, &mut state) {
        operation.finish_state(state);
        update_tray(app, runtime);
        return Err(present_error(error));
    }
    operation.finish_state(state);
    runtime.refresh_linux_candidate_recovery_pending();
    *runtime.session.lock().expect("session lock") = None;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    invalidate_pending_confirmation(runtime);
    update_tray(app, runtime);
    Ok(runtime.view())
}

fn persist_intent(runtime: &Runtime, state: &mut DesktopState) -> CoreResult<()> {
    if state.has_pending_disconnect_cleanup() {
        return Ok(());
    }
    let intent = DisconnectCleanupIntent::for_disconnect_pairs(
        state.pairs().cloned().collect(),
        LinuxCredentialStore::disconnect_credential_slots()?,
    )?;
    let mut next = state.clone();
    next.begin_disconnect_cleanup(intent)?;
    runtime.store.save(&next)?;
    *state = next;
    Ok(())
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
    complete_local_cleanup_with_slot_cleanup(
        store,
        state,
        finalize,
        LinuxCredentialStore::delete_and_verify_disconnect_credential_slot,
    )
}

pub(crate) fn complete_local_cleanup_with_slot_cleanup(
    store: &StateStore,
    state: &mut DesktopState,
    finalize: impl FnOnce(&mut DesktopState) -> CoreResult<()>,
    mut cleanup_slot: impl FnMut(&DisconnectCredentialSlot) -> CoreResult<()>,
) -> CoreResult<()> {
    if !state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
    {
        return Err(DesktopError::InvalidState(
            "disconnect local cleanup cannot run before remote retirement".to_string(),
        ));
    }
    while let Some(marker) = state
        .pending_disconnect_cleanup()
        .and_then(|cleanup| cleanup.marker.clone())
    {
        let guard = UnixRootGuard::acquire(
            &marker.local_root,
            marker.marker.local_root_identity.as_ref(),
        )?;
        guard.remove_exact_pair_marker(&marker.marker)?;
        save_progress(store, state, |cleanup| {
            cleanup.acknowledge_marker();
            Ok(())
        })?;
    }
    while let Some(slot) = state
        .pending_disconnect_cleanup()
        .and_then(|cleanup| cleanup.next_credential_slot().cloned())
    {
        cleanup_slot(&slot)?;
        save_progress(store, state, |cleanup| {
            cleanup.acknowledge_credential_slot(&slot)
        })?;
    }
    if state.has_pending_disconnect_cleanup() {
        let mut next = state.clone();
        finalize(&mut next)?;
        if next.last_error.as_deref() == Some(CLEANUP_PENDING) {
            next.last_error = None;
        }
        store.save(&next)?;
        *state = next;
    }
    Ok(())
}

fn save_progress(
    store: &StateStore,
    state: &mut DesktopState,
    advance: impl FnOnce(&mut DisconnectCleanupIntent) -> CoreResult<()>,
) -> CoreResult<()> {
    let mut next = state.clone();
    advance(next.pending_disconnect_cleanup_mut().ok_or_else(|| {
        DesktopError::InvalidState("disconnect cleanup is not pending".to_string())
    })?)?;
    store.save(&next)?;
    *state = next;
    Ok(())
}

fn present_error(error: DesktopError) -> String {
    error.to_string()
}

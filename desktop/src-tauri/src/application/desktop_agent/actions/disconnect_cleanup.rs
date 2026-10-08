//! Local cleanup retained after capability-authenticated remote retirement.

use shellx_drive_desktop_core::{
    DesktopAgentDisconnectContinuation, DesktopAgentDisconnectPhase, DesktopError,
    DisconnectCleanupIntent, LifecycleOperation, Result as CoreResult,
};

use super::super::Runtime;

/// Persist the exact local scope and the agent-owned remote continuation in one
/// state image. A failed save publishes neither half of this recovery contract.
pub(in crate::application::desktop_agent) fn persist_agent_disconnect_admission(
    runtime: &Runtime,
    operation: &mut LifecycleOperation,
    continuation: DesktopAgentDisconnectContinuation,
) -> CoreResult<()> {
    let saved = runtime.coordinator.snapshot();
    let credential_slots =
        crate::application::connection_credentials::cleanup_slots(runtime, &saved)?;

    let mut state = runtime.coordinator.snapshot();
    if state.has_pending_disconnect_cleanup() || state.pending_desktop_agent_disconnect().is_some()
    {
        return Err(DesktopError::InvalidState(
            "Disconnect recovery is already pending".to_string(),
        ));
    }
    state.begin_disconnect_cleanup(DisconnectCleanupIntent::for_disconnect_pairs(
        state.pairs().cloned().collect(),
        credential_slots,
    )?)?;
    state.begin_desktop_agent_disconnect(continuation)?;
    runtime.store.save(&state)?;
    operation.finish_state(state);
    Ok(())
}

/// Finish only the retained local work after the broker accepted
/// `disconnect-retire`. This never sends a normal owner or device retirement
/// request, because those credentials have deliberately become invalid.
pub(in crate::application::desktop_agent) fn complete_agent_disconnect_local_cleanup(
    runtime: &Runtime,
) -> CoreResult<()> {
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let mut state = runtime.coordinator.snapshot();
    if !matches!(
        state
            .pending_desktop_agent_disconnect()
            .map(|continuation| continuation.phase),
        Some(DesktopAgentDisconnectPhase::LocalCleanup)
    ) {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect local cleanup has no retired continuation".to_string(),
        ));
    }
    if !state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
        || state.pair.is_some()
    {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect local cleanup has no disconnected retired state".to_string(),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        crate::application::linux::disconnect::complete_local_cleanup_with_finalizer(
            &runtime.store,
            &mut state,
            shellx_drive_desktop_core::DesktopState::finish_agent_disconnect_cleanup,
        )?;
    }
    #[cfg(target_os = "macos")]
    crate::application::macos::offboarding::complete_local_cleanup_with_finalizer(
        &runtime.store,
        &mut state,
        shellx_drive_desktop_core::DesktopState::finish_agent_disconnect_cleanup,
    )?;
    #[cfg(target_os = "windows")]
    {
        crate::application::windows::disconnect_cleanup::complete_local_cleanup_with_finalizer(
            &runtime.store,
            &mut state,
            shellx_drive_desktop_core::DesktopState::finish_agent_disconnect_cleanup,
        )?;
    }

    operation.finish_state(state);
    Ok(())
}

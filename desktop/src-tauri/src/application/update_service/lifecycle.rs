use shellx_drive_desktop_core::{
    DesktopUpdateRestartReadback, LifecycleOperation, Result as CoreResult,
};

use super::{DesktopUpdateServiceError, Runtime};

pub(crate) fn reconcile_desktop_update_restart(
    runtime: &Runtime,
) -> CoreResult<DesktopUpdateRestartReadback> {
    runtime.ensure_state_available()?;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let mut state = runtime.coordinator.snapshot();
    let readback = state.read_desktop_update_restart(env!("CARGO_PKG_VERSION"))?;
    if matches!(readback, DesktopUpdateRestartReadback::Applied { .. }) {
        runtime.store.save(&state)?;
        operation.finish_state(state);
    }
    runtime.note_update_restart_readback(&readback);
    Ok(readback)
}

pub(super) struct UpdateLifecycle {
    pub(super) state: shellx_drive_desktop_core::DesktopState,
    pub(super) operation: LifecycleOperation,
}

impl UpdateLifecycle {
    pub(super) fn cancel(&mut self, runtime: &Runtime, candidate_id: &str) -> CoreResult<()> {
        self.state.cancel_desktop_update_restart(candidate_id)?;
        runtime.store.save(&self.state)?;
        self.operation.publish_persisted_state(self.state.clone())
    }
}

pub(super) fn persist_restart_intent(
    runtime: &Runtime,
    target_version: &str,
    candidate_id: &str,
    agent_command_id: Option<&str>,
) -> Result<UpdateLifecycle, DesktopUpdateServiceError> {
    runtime.ensure_disconnect_cleanup_complete()?;
    runtime.require_candidate_recovery_complete()?;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    runtime.ensure_disconnect_cleanup_complete()?;
    runtime.require_candidate_recovery_complete()?;
    let mut state = runtime.coordinator.snapshot();
    if let Some(command_id) = agent_command_id {
        state.record_desktop_update_restart_for_agent(
            target_version.to_string(),
            candidate_id.to_string(),
            command_id.to_string(),
        )?;
    } else {
        state
            .record_desktop_update_restart(target_version.to_string(), candidate_id.to_string())?;
    }
    runtime.store.save(&state)?;
    operation.publish_persisted_state(state.clone())?;
    runtime.clear_update_recovery_target_version();
    Ok(UpdateLifecycle { state, operation })
}

#[cfg(test)]
#[path = "lifecycle/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "lifecycle/persistence_tests.rs"]
mod persistence_tests;

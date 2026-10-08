//! Agent-only updater continuation with an exact durable broker journal.

use std::{future::Future, pin::Pin};

use chrono::Utc;
use shellx_drive_desktop_core::{
    DesktopAgentProgressPhase, DesktopAgentProgressReport, DesktopState, DriveHttpClient,
    LifecycleOperation, Result as CoreResult,
};
use tauri::{AppHandle, Manager};

use crate::application::update_service::{
    DesktopUpdateLifecycleHook, DesktopUpdateLifecycleStage, DesktopUpdateService,
    DesktopUpdateServiceError,
};

use super::{
    command_outcome_for_error, current_agent_assertion, CommandExecution, CommandOutcome, Runtime,
};

pub(super) async fn install(
    app: &AppHandle,
    runtime: &Runtime,
    client: &DriveHttpClient,
    device_credential: &str,
    command_id: &str,
    lease_id: &str,
    candidate_id: String,
) -> CommandExecution {
    let service = app.state::<DesktopUpdateService>();
    let mut hook = AgentUpdateLifecycleHook {
        runtime,
        client,
        device_credential,
        command_id,
        lease_id,
    };
    match service
        .install_for_agent(app, runtime, &candidate_id, command_id, &mut hook, |_| {})
        .await
    {
        Ok(()) => CommandExecution::RelaunchPending,
        Err(error) => CommandExecution::Terminal(outcome_for_update_error(error)),
    }
}

fn outcome_for_update_error(error: DesktopUpdateServiceError) -> CommandOutcome {
    match error {
        DesktopUpdateServiceError::Lifecycle(error) => command_outcome_for_error(&error),
        DesktopUpdateServiceError::NoCheckedUpdate
        | DesktopUpdateServiceError::CandidateMismatch
        | DesktopUpdateServiceError::InProgress
        | DesktopUpdateServiceError::StateUnavailable
        | DesktopUpdateServiceError::Updater(_) => CommandOutcome::failed(),
    }
}

struct AgentUpdateLifecycleHook<'a> {
    runtime: &'a Runtime,
    client: &'a DriveHttpClient,
    device_credential: &'a str,
    command_id: &'a str,
    lease_id: &'a str,
}

impl DesktopUpdateLifecycleHook for AgentUpdateLifecycleHook<'_> {
    fn report<'a>(
        &'a mut self,
        stage: DesktopUpdateLifecycleStage,
        state: &'a mut DesktopState,
        operation: &'a mut LifecycleOperation,
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let phase = match stage {
                DesktopUpdateLifecycleStage::Updating => DesktopAgentProgressPhase::Updating,
                DesktopUpdateLifecycleStage::RelaunchPending => {
                    DesktopAgentProgressPhase::RelaunchPending
                }
            };
            let event_sequence = if phase == DesktopAgentProgressPhase::RelaunchPending {
                state
                    .desktop_agent_control
                    .begin_relaunch_pending(self.command_id, Utc::now())?
            } else {
                state
                    .desktop_agent_control
                    .begin_progress(self.command_id, phase, Utc::now())?
            };
            self.runtime.store.save(state)?;
            operation.publish_persisted_state(state.clone())?;
            let assertion = current_agent_assertion(self.runtime)?;
            self.client
                .report_desktop_agent_progress(
                    self.device_credential,
                    DesktopAgentProgressReport {
                        command_id: self.command_id,
                        lease_id: self.lease_id,
                        event_sequence,
                        assertion: &assertion,
                        phase,
                        progress_basis_points: None,
                    },
                )
                .await?;
            state.desktop_agent_control.mark_progress_reported(
                self.command_id,
                event_sequence,
                phase,
                Utc::now(),
            )?;
            self.runtime.store.save(state)?;
            operation.publish_persisted_state(state.clone())
        })
    }
}

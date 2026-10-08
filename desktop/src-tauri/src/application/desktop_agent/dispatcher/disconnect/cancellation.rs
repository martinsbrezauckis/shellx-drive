use shellx_drive_desktop_core::{
    DesktopAgentCommandJournalState, DesktopAgentDeviceAssertion,
    DesktopAgentDisconnectContinuation, DesktopAgentDisconnectPhase, DesktopAgentJournalRecovery,
    DesktopAgentTerminalCode, DesktopAgentTerminalStatus, DesktopError, Result as CoreResult,
};

use super::Runtime;

pub(super) fn pending_cancelled_continuation(
    runtime: &Runtime,
) -> CoreResult<DesktopAgentDisconnectContinuation> {
    let continuation = runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect cancellation continuation is unavailable".to_string(),
            )
        })?;
    if continuation.phase != DesktopAgentDisconnectPhase::RetirementCancelled {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect cancellation is not pending".to_string(),
        ));
    }
    continuation.validate()?;
    Ok(continuation)
}

pub(super) fn cancelled_retirement_terminal_is_accepted(
    runtime: &Runtime,
    continuation: &DesktopAgentDisconnectContinuation,
) -> CoreResult<bool> {
    let state = runtime.coordinator.snapshot();
    let assertion = continuation.retire_assertion.as_ref().ok_or_else(|| {
        DesktopError::InvalidState(
            "desktop-agent Disconnect cancellation has no persisted assertion".to_string(),
        )
    })?;
    let entry = state
        .desktop_agent_control
        .command_journal
        .iter()
        .find(|entry| entry.command_id == continuation.command_id)
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect cancellation has no durable journal entry".to_string(),
            )
        })?;
    Ok(entry.state == DesktopAgentCommandJournalState::Interrupted
        && entry.lease_id == continuation.lease_id
        && entry.terminal_event_sequence == Some(continuation.completion_event_sequence)
        && entry.terminal_code == Some(DesktopAgentTerminalCode::CancellationRequested)
        && entry.result_code.is_none()
        && entry.result.is_none()
        && assertion.last_terminal_command_id.as_deref() == Some(continuation.command_id.as_str()))
}

pub(super) fn cancelled_retirement_terminal(
    runtime: &Runtime,
    continuation: &DesktopAgentDisconnectContinuation,
) -> CoreResult<(DesktopAgentJournalRecovery, DesktopAgentDeviceAssertion)> {
    let state = runtime.coordinator.snapshot();
    let assertion = continuation.retire_assertion.clone().ok_or_else(|| {
        DesktopError::InvalidState(
            "desktop-agent Disconnect cancellation has no persisted assertion".to_string(),
        )
    })?;
    let retry = state
        .desktop_agent_control
        .terminal_reports()?
        .into_iter()
        .find(|retry| retry.command_id == continuation.command_id)
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect cancellation has no persisted terminal retry".to_string(),
            )
        })?;
    if retry.lease_id != continuation.lease_id
        || retry.event_sequence != continuation.completion_event_sequence
        || retry.terminal_status != DesktopAgentTerminalStatus::Interrupted
        || retry.terminal_code != DesktopAgentTerminalCode::CancellationRequested
        || retry.result_code.is_some()
        || retry.result.is_some()
        || assertion.last_terminal_command_id.as_deref() != Some(continuation.command_id.as_str())
    {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect cancellation retry does not match its durable witness"
                .to_string(),
        ));
    }
    Ok((retry, assertion))
}

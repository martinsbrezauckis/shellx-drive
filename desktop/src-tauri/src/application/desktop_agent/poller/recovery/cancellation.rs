//! Exact cancellation conversion for response-lost generic broker events.

use chrono::Utc;
use shellx_drive_desktop_core::{
    DesktopAgentAbandonmentReason, DesktopAgentCommandEventDisposition,
    DesktopAgentDeviceAssertion, DesktopAgentJournalRecovery, DesktopAgentTerminalReport,
    DesktopError, DesktopState, DriveHttpClient, Result as CoreResult,
};

use super::super::super::{update_agent_state, update_desktop_state, Runtime};

pub(super) async fn report_terminal_retry(
    client: &DriveHttpClient,
    device_credential: &str,
    retry: &DesktopAgentJournalRecovery,
    assertion: &DesktopAgentDeviceAssertion,
) -> CoreResult<DesktopAgentCommandEventDisposition> {
    client
        .report_desktop_agent_terminal_with_disposition(
            device_credential,
            DesktopAgentTerminalReport {
                command_id: &retry.command_id,
                lease_id: &retry.lease_id,
                event_sequence: retry.event_sequence,
                assertion,
                status: retry.terminal_status,
                terminal_code: retry.terminal_code,
                result_code: retry.result_code,
                result: retry.result.as_ref(),
            },
        )
        .await
}

pub(super) async fn report_replaced_cancellation_terminal(
    runtime: &Runtime,
    client: &DriveHttpClient,
    device_credential: &str,
    cancellation: &DesktopAgentJournalRecovery,
    assertion: &DesktopAgentDeviceAssertion,
    update_candidate_id: Option<&str>,
) -> CoreResult<()> {
    match report_terminal_retry(client, device_credential, cancellation, assertion).await {
        Ok(DesktopAgentCommandEventDisposition::Accepted) => {
            mark_terminal_retry_reported(runtime, cancellation, update_candidate_id)
        }
        Ok(DesktopAgentCommandEventDisposition::CancellationRequested) => {
            Err(DesktopError::InvalidState(
                "desktop-agent cancellation terminal was not accepted".to_string(),
            ))
        }
        Err(error) => {
            if let Some(reason) = abandonment_reason(&error) {
                update_agent_state(runtime, |control| {
                    control.abandon(&cancellation.command_id, reason, Utc::now())
                })?;
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

pub(super) fn mark_terminal_retry_reported(
    runtime: &Runtime,
    retry: &DesktopAgentJournalRecovery,
    update_candidate_id: Option<&str>,
) -> CoreResult<()> {
    update_desktop_state(runtime, |state| {
        state
            .desktop_agent_control
            .mark_terminal_reported(&retry.command_id, Utc::now())?;
        if let Some(candidate_id) = update_candidate_id {
            state.complete_desktop_update_restart_for_agent(candidate_id, &retry.command_id)?;
        }
        Ok(())
    })
}

pub(super) fn abandonment_reason(error: &DesktopError) -> Option<DesktopAgentAbandonmentReason> {
    match error {
        DesktopError::Server {
            status: 401 | 403, ..
        } => Some(DesktopAgentAbandonmentReason::AuthorizationLost),
        DesktopError::Server { status: 409, .. } => {
            Some(DesktopAgentAbandonmentReason::BrokerConflict)
        }
        DesktopError::Server {
            status: 404 | 410, ..
        } => Some(DesktopAgentAbandonmentReason::CommandUnavailable),
        _ => None,
    }
}

pub(super) fn matching_agent_restart_candidate(
    state: &DesktopState,
    command_id: &str,
) -> Option<String> {
    state
        .pending_desktop_update_restart
        .as_ref()
        .filter(|intent| intent.agent_command_id() == Some(command_id))
        .and_then(|intent| intent.candidate_id())
        .map(str::to_string)
}

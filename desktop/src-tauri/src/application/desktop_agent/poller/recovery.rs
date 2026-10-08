//! Durable recovery for response-loss and post-restart broker work.

use chrono::Utc;
use shellx_drive_desktop_core::{
    DesktopAgentCommandEventDisposition, DesktopAgentProgressReport, DriveHttpClient,
    Result as CoreResult,
};

use super::super::{current_agent_assertion, device_credential, update_agent_state, Runtime};

mod cancellation;
use cancellation::{
    abandonment_reason, mark_terminal_retry_reported, matching_agent_restart_candidate,
    report_replaced_cancellation_terminal, report_terminal_retry,
};

/// No poll overlaps another poll for a device. At the start of a cycle any
/// nonterminal journal record therefore belongs to a previous interrupted
/// cycle or desktop restart, never to an in-flight local dispatcher.
pub(super) async fn recover_unfinished_commands(runtime: &Runtime) -> CoreResult<()> {
    retry_pending_progress_reports(runtime).await?;
    complete_restarted_update_if_proven(runtime)?;
    let now = Utc::now();
    let current = runtime.coordinator.snapshot().desktop_agent_control;
    let mut interrupted = current.clone();
    interrupted.interrupt_after_restart(now);
    if interrupted == current {
        return retry_pending_terminal_reports(runtime).await;
    }
    update_agent_state(runtime, |control| {
        *control = interrupted;
        Ok(())
    })?;
    retry_pending_terminal_reports(runtime).await
}

fn complete_restarted_update_if_proven(runtime: &Runtime) -> CoreResult<()> {
    let mut state = runtime.coordinator.snapshot();
    let shellx_drive_desktop_core::DesktopUpdateRestartReadback::Applied {
        version,
        candidate_id: Some(candidate_id),
        agent_command_id: Some(command_id),
    } = state.read_desktop_update_restart(env!("CARGO_PKG_VERSION"))?
    else {
        return Ok(());
    };
    if !state.desktop_agent_control.is_relaunch_pending(&command_id) {
        return Ok(());
    }
    update_agent_state(runtime, |control| {
        control.complete_relaunched_update(&command_id, candidate_id, version, Utc::now())
    })
}

async fn retry_pending_progress_reports(runtime: &Runtime) -> CoreResult<()> {
    let retries = runtime
        .coordinator
        .snapshot()
        .desktop_agent_control
        .pending_progress_reports()?;
    if retries.is_empty() {
        return Ok(());
    }
    let (_, device_credential) = device_credential(runtime)?;
    let assertion = current_agent_assertion(runtime)?;
    let session = runtime.current_session()?;
    let client = DriveHttpClient::new(&session.server_url)?;
    for retry in retries {
        let outcome = client
            .report_desktop_agent_progress_with_disposition(
                &device_credential,
                DesktopAgentProgressReport {
                    command_id: &retry.command_id,
                    lease_id: &retry.lease_id,
                    event_sequence: retry.event_sequence,
                    assertion: &assertion,
                    phase: retry.phase,
                    progress_basis_points: None,
                },
            )
            .await;
        match outcome {
            Ok(DesktopAgentCommandEventDisposition::Accepted) => {
                update_agent_state(runtime, |control| {
                    control.mark_progress_reported(
                        &retry.command_id,
                        retry.event_sequence,
                        retry.phase,
                        Utc::now(),
                    )
                })?;
            }
            Ok(DesktopAgentCommandEventDisposition::CancellationRequested) => {
                let update_candidate_id = matching_agent_restart_candidate(
                    &runtime.coordinator.snapshot(),
                    &retry.command_id,
                );
                let cancellation = update_agent_state(runtime, |control| {
                    control.replace_pending_progress_with_cancellation(
                        &retry.command_id,
                        retry.event_sequence,
                        Utc::now(),
                    )
                })?;
                let mut cancellation_assertion = assertion.clone();
                cancellation_assertion.last_terminal_command_id =
                    Some(cancellation.command_id.clone());
                report_replaced_cancellation_terminal(
                    runtime,
                    &client,
                    &device_credential,
                    &cancellation,
                    &cancellation_assertion,
                    update_candidate_id.as_deref(),
                )
                .await?;
            }
            Err(error) => {
                if let Some(reason) = abandonment_reason(&error) {
                    update_agent_state(runtime, |control| {
                        control.abandon(&retry.command_id, reason, Utc::now())
                    })?;
                    continue;
                }
                return Err(error);
            }
        }
    }
    Ok(())
}

async fn retry_pending_terminal_reports(runtime: &Runtime) -> CoreResult<()> {
    let retries = runtime
        .coordinator
        .snapshot()
        .desktop_agent_control
        .terminal_reports()?;
    if retries.is_empty() {
        return Ok(());
    }
    let (_, device_credential) = device_credential(runtime)?;
    let assertion = current_agent_assertion(runtime)?;
    let session = runtime.current_session()?;
    let client = DriveHttpClient::new(&session.server_url)?;
    for retry in retries {
        let update_candidate_id =
            matching_agent_restart_candidate(&runtime.coordinator.snapshot(), &retry.command_id);
        let mut retry_assertion = assertion.clone();
        retry_assertion.last_terminal_command_id = Some(retry.command_id.clone());
        let outcome =
            report_terminal_retry(&client, &device_credential, &retry, &retry_assertion).await;
        match outcome {
            Ok(DesktopAgentCommandEventDisposition::Accepted) => {
                mark_terminal_retry_reported(runtime, &retry, update_candidate_id.as_deref())?;
            }
            Ok(DesktopAgentCommandEventDisposition::CancellationRequested) => {
                let cancellation = update_agent_state(runtime, |control| {
                    control
                        .replace_pending_terminal_with_cancellation(&retry.command_id, Utc::now())
                })?;
                report_replaced_cancellation_terminal(
                    runtime,
                    &client,
                    &device_credential,
                    &cancellation,
                    &retry_assertion,
                    update_candidate_id.as_deref(),
                )
                .await?;
            }
            Err(error) => {
                if let Some(reason) = abandonment_reason(&error) {
                    update_agent_state(runtime, |control| {
                        control.abandon(&retry.command_id, reason, Utc::now())
                    })?;
                    continue;
                }
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "recovery/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "recovery/idle_tests.rs"]
mod idle_tests;

#[cfg(test)]
#[path = "recovery/cancellation_tests.rs"]
mod cancellation_tests;

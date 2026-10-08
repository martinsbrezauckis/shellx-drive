use chrono::Utc;
use shellx_drive_desktop_core::{
    DesktopAgentProgressReport, DesktopError, DriveHttpClient, Result as CoreResult,
};
use std::{sync::atomic::Ordering, time::Duration};
use tauri::{AppHandle, Manager};

mod command;
mod disconnect;
mod recovery;
mod revocation;
pub(crate) use disconnect::resume_agent_disconnect_completion;
use recovery::recover_unfinished_commands;
use revocation::{reconcile_external_device_revocation, reconcile_missing_device_credential};

use super::{
    current_agent_assertion, device_credential,
    dispatcher::{execute_typed_command, CommandLease},
    update_agent_state, Runtime,
};
const AGENT_POLL_INTERVAL: Duration = Duration::from_secs(20);

fn agent_next_event_sequence(runtime: &Runtime, command_id: &str) -> CoreResult<u64> {
    runtime
        .coordinator
        .snapshot()
        .desktop_agent_control
        .next_event_sequence(command_id)
}

/// Start an outbound broker poll only after local enrollment. It opens no
/// listener and exits when local disable or Disconnect cleanup takes effect.
pub(crate) fn start_polling(app: &AppHandle, runtime: &Runtime) {
    if !runtime.coordinator.snapshot().desktop_agent_control.enabled
        || runtime.candidate_recovery_pending()
        || runtime
            .coordinator
            .snapshot()
            .has_pending_disconnect_cleanup()
        || runtime.agent_polling_enabled.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let generation = runtime.agent_poll_generation.fetch_add(1, Ordering::AcqRel) + 1;
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let runtime = app.state::<Runtime>();
        loop {
            if !runtime.agent_polling_enabled.load(Ordering::Acquire)
                || runtime.agent_poll_generation.load(Ordering::Acquire) != generation
            {
                break;
            }
            match reconcile_missing_device_credential(&runtime).await {
                Ok(true) => {
                    stop_polling(&runtime);
                    break;
                }
                Ok(false) => {}
                Err(error) => {
                    eprintln!(
                        "ShellX Drive desktop-agent missing-credential revocation reconciliation \
                         did not complete: {error}"
                    );
                    tokio::time::sleep(AGENT_POLL_INTERVAL).await;
                    continue;
                }
            }
            if let Err(error) = poll_once(&app, &runtime).await {
                // `poll_once` makes only device-bearer broker requests. A
                // 401 therefore permits an independently owner-authenticated
                // exact-device revocation check; every other response keeps
                // the local enrollment and its credential intact.
                match reconcile_external_device_revocation(&runtime, &error).await {
                    Ok(true) => {
                        stop_polling(&runtime);
                        break;
                    }
                    Ok(false) => {
                        eprintln!("ShellX Drive desktop-agent poll did not complete: {error}");
                    }
                    Err(reconciliation_error) => {
                        eprintln!(
                            "ShellX Drive desktop-agent poll did not complete: {error}; \
                             external revocation reconciliation did not complete: {reconciliation_error}"
                        );
                    }
                }
            }
            tokio::time::sleep(AGENT_POLL_INTERVAL).await;
        }
    });
}

pub(crate) fn stop_polling(runtime: &Runtime) {
    runtime
        .agent_polling_enabled
        .store(false, Ordering::Release);
    runtime.agent_poll_generation.fetch_add(1, Ordering::AcqRel);
}

/// Persisted Disconnect intent freezes this exact broker device before any
/// remote retirement or local credential deletion. A failure leaves the
/// cleanup journal intact and prevents cleanup from advancing.
pub(crate) async fn freeze_for_pending_disconnect(runtime: &Runtime) -> CoreResult<()> {
    if !runtime.coordinator.snapshot().desktop_agent_control.enabled {
        return Ok(());
    }
    let (device_id, credential) = device_credential(runtime)?;
    let assertion = current_agent_assertion(runtime)?;
    if !assertion.pending_disconnect_cleanup {
        return Err(DesktopError::InvalidState(
            "desktop-agent freeze requires durable Disconnect cleanup".to_string(),
        ));
    }
    let session = runtime.current_session()?;
    let client = DriveHttpClient::new(&session.server_url)?;
    client
        .heartbeat_desktop_agent_device(&device_id, &credential, &assertion)
        .await
}

/// Revoke the exact device after its pending Disconnect intent was frozen.
/// The caller owns the lifecycle operation and persists the resulting control
/// state before it retires the normal Drive session or removes local secrets.
pub(crate) async fn revoke_for_pending_disconnect(
    runtime: &Runtime,
    state: &mut shellx_drive_desktop_core::DesktopState,
) -> CoreResult<()> {
    if !state.desktop_agent_control.enabled {
        return Ok(());
    }
    if !state.has_pending_disconnect_cleanup() {
        return Err(DesktopError::InvalidState(
            "desktop-agent revoke requires durable Disconnect cleanup".to_string(),
        ));
    }
    let device_id = state
        .desktop_agent_control
        .device_id
        .as_deref()
        .ok_or_else(|| {
            DesktopError::InvalidState("desktop-agent enrollment has no device ID".to_string())
        })?
        .to_string();
    let session = runtime.current_session()?;
    let owner_bearer = runtime.current_token(&session)?;
    DriveHttpClient::new(&session.server_url)?
        .revoke_desktop_agent_device(&device_id, &owner_bearer)
        .await?;
    state.clear_desktop_agent_disconnect_retirement_block()?;
    state.retire_desktop_agent_control();
    Ok(())
}

async fn poll_once(app: &AppHandle, runtime: &Runtime) -> CoreResult<()> {
    recover_unfinished_commands(runtime).await?;
    let (device_id, device_credential) = device_credential(runtime)?;
    let assertion = current_agent_assertion(runtime)?;
    let session = runtime.current_session()?;
    let client = DriveHttpClient::new(&session.server_url)?;
    if assertion.pending_disconnect_cleanup || assertion.candidate_recovery {
        client
            .heartbeat_desktop_agent_device(&device_id, &device_credential, &assertion)
            .await?;
        return Ok(());
    }
    let Some(claim) = client
        .claim_desktop_agent_command(&device_id, &device_credential, &assertion)
        .await?
    else {
        return Ok(());
    };
    let command = claim.parse_command()?;
    let command_id = claim.command_id.clone();
    let lease_id = claim.lease_id.clone();
    let lease_expires_at = claim.lease_expires_at;
    update_agent_state(runtime, |control| {
        control.record_lease(command_id.clone(), lease_id.clone(), claim.kind, Utc::now())
    })?;
    let acknowledgement_sequence = agent_next_event_sequence(runtime, &command_id)?;
    client
        .acknowledge_desktop_agent_command(
            &device_credential,
            &command_id,
            &lease_id,
            acknowledgement_sequence,
            &assertion,
        )
        .await?;
    let persisted_acknowledgement_sequence = update_agent_state(runtime, |control| {
        control.mark_acknowledged(&command_id, Utc::now())
    })?;
    if persisted_acknowledgement_sequence != acknowledgement_sequence {
        return Err(DesktopError::InvalidState(
            "desktop-agent acknowledgement sequence changed during persistence".to_string(),
        ));
    }
    let progress_phase = shellx_drive_desktop_core::DesktopAgentProgressPhase::Accepted;
    let progress_sequence = update_agent_state(runtime, |control| {
        control.begin_progress(&command_id, progress_phase, Utc::now())
    })?;
    // The durable event may have reached the broker after its response was
    // lost. Leave it pending for an exact idempotent retry before any terminal
    // outcome can consume a later sequence.
    client
        .report_desktop_agent_progress(
            &device_credential,
            DesktopAgentProgressReport {
                command_id: &command_id,
                lease_id: &lease_id,
                event_sequence: progress_sequence,
                assertion: &assertion,
                phase: progress_phase,
                progress_basis_points: None,
            },
        )
        .await?;
    update_agent_state(runtime, |control| {
        control.mark_progress_reported(&command_id, progress_sequence, progress_phase, Utc::now())
    })?;
    let lease = CommandLease {
        client: &client,
        device_credential: &device_credential,
        command_id: &command_id,
        lease_id: &lease_id,
        expires_at: lease_expires_at,
        disconnect_completion_capability: claim.disconnect_completion_capability.as_deref(),
        disconnect_completion_expires_at: claim.disconnect_completion_expires_at,
    };
    let execution = execute_typed_command(app, runtime, &lease, command).await;
    finish_command_execution(app, runtime, lease, execution).await
}
use command::finish_command_execution;

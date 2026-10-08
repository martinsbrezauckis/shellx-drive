//! Agent-owned Disconnect retirement and exact post-cleanup completion.

use super::{CommandLease, Runtime};
use crate::application::{
    desktop_agent::{
        actions::{
            bound_agent_owner_session, complete_agent_disconnect_local_cleanup,
            persist_agent_disconnect_admission, retire_non_bound_agent_sessions,
        },
        current_agent_assertion, remove_exact_agent_credential, update_desktop_state,
        write_exact_agent_credential,
    },
    invalidate_pending_confirmation, request_disconnect_after_sync,
};
use chrono::Utc;
use shellx_drive_desktop_core::{
    desktop_agent_disconnect_credential_key, validate_disconnect_completion_capability,
    DesktopAgentCommandKind, DesktopAgentDisconnectContinuation, DesktopAgentDisconnectPhase,
    DesktopAgentDisconnectTerminalReceipt, DesktopAgentDisconnectTransportError,
    DesktopAgentTerminalReport, DesktopError, DriveHttpClient, RemoteSessionRecord,
    Result as CoreResult,
};

#[cfg(test)]
#[path = "disconnect/admission_tests.rs"]
mod admission_tests;
mod cancellation;
mod disposition;

use cancellation::{
    cancelled_retirement_terminal, cancelled_retirement_terminal_is_accepted,
    pending_cancelled_continuation,
};
use disposition::{
    block_completion_after_deadline, block_completion_for_missing_capability,
    block_retirement_for_missing_capability, blocked_reason, disconnect_deadline_reached,
    finalize_blocked_disposition, finalize_cancelled_retirement, read_capability,
    retirement_blocked_reason,
};

pub(super) enum Execution {
    Completed,
    Cancelled,
    Blocked,
}

enum Retirement {
    Retired,
    CancelledBeforeAdmission,
    Blocked,
}

pub(super) async fn execute(runtime: &Runtime, lease: &CommandLease<'_>) -> CoreResult<Execution> {
    preflight_disconnect_admission(runtime, lease)?;
    let _offboarding = runtime.auth_offboarding.begin_offboarding()?;
    let mut disconnect = request_disconnect_after_sync(runtime).await?;
    let _publication = runtime.auth_publication.lock().await;
    let mut operation = disconnect.try_begin()?.ok_or_else(|| {
        DesktopError::InvalidState(
            "synchronization restarted while Disconnect was pending".to_string(),
        )
    })?;
    let bound_owner_session = bound_agent_owner_session(runtime)?;
    let session = runtime.current_session()?;
    let origin = session.server_url.trim_end_matches('/').to_string();
    let capability_key = desktop_agent_disconnect_credential_key(&origin, lease.command_id);
    let mut assertion = current_agent_assertion(runtime)?;
    assertion.pending_disconnect_cleanup = true;
    let completion_event_sequence = runtime
        .coordinator
        .snapshot()
        .desktop_agent_control
        .next_event_sequence(lease.command_id)?;
    let (capability, completion_expires_at) = required_capability(lease)?;
    // This state write precedes both raw capability storage and every remote
    // mutation. A crash can therefore recover the exact locator rather than
    // orphaning a credential-store entry or a partial remote retirement.
    persist_agent_disconnect_admission(
        runtime,
        &mut operation,
        DesktopAgentDisconnectContinuation {
            canonical_server_origin: origin.clone(),
            command_id: lease.command_id.to_string(),
            lease_id: lease.lease_id.to_string(),
            retirement_expires_at: Some(lease.expires_at),
            completion_expires_at,
            completion_event_sequence,
            phase: DesktopAgentDisconnectPhase::RetiringRemote,
            retire_assertion: Some(assertion),
            bound_owner_session: Some(bound_owner_session.clone()),
            terminal_receipt: None,
            blocked_reason: None,
        },
    )?;
    super::super::poller::stop_polling(runtime);
    write_exact_agent_credential(
        runtime.platform.desktop_agent_disconnect_credentials(),
        &capability_key,
        capability,
    )?;
    retire_non_bound_agent_sessions(runtime, &bound_owner_session).await?;
    match retire_remote(runtime).await? {
        Retirement::Retired => complete_after_retirement(runtime).await,
        Retirement::CancelledBeforeAdmission => complete_cancelled_retirement(runtime).await,
        Retirement::Blocked => Ok(Execution::Blocked),
    }
}

pub(in crate::application::desktop_agent) async fn resume(runtime: &Runtime) -> CoreResult<()> {
    let _offboarding = runtime.auth_offboarding.begin_offboarding()?;
    let _publication = runtime.auth_publication.lock().await;
    let Some(continuation) = runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()
    else {
        return Ok(());
    };
    match continuation.phase {
        DesktopAgentDisconnectPhase::RetiringRemote => {
            let bound_owner_session =
                continuation.bound_owner_session.as_ref().ok_or_else(|| {
                    DesktopError::InvalidState(
                        "desktop-agent Disconnect retirement has no bound session witness"
                            .to_string(),
                    )
                })?;
            if !retirement_retry_is_locally_admitted(runtime, &continuation)? {
                return Ok(());
            }
            retire_non_bound_agent_sessions(runtime, bound_owner_session).await?;
            match retire_remote(runtime).await? {
                Retirement::Retired => {
                    complete_after_retirement(runtime).await?;
                }
                Retirement::CancelledBeforeAdmission => {
                    complete_cancelled_retirement(runtime).await?;
                }
                Retirement::Blocked => {}
            }
            Ok(())
        }
        DesktopAgentDisconnectPhase::LocalCleanup | DesktopAgentDisconnectPhase::Reporting => {
            complete_after_retirement(runtime).await.map(|_| ())
        }
        DesktopAgentDisconnectPhase::TerminalAccepted => {
            finalize_accepted_terminal(runtime).map(|_| ())
        }
        DesktopAgentDisconnectPhase::RetirementCancelled => {
            complete_cancelled_retirement(runtime).await.map(|_| ())
        }
        DesktopAgentDisconnectPhase::RetirementBlocked
        | DesktopAgentDisconnectPhase::CompletionBlocked => finalize_blocked_disposition(runtime),
    }
}

/// Verify the exact local prerequisites before resuming non-bound remote
/// retirement. This avoids revoking another session after a crash that lost
/// the raw completion capability before the bound capability retirement could
/// begin.
fn retirement_retry_is_locally_admitted(
    runtime: &Runtime,
    continuation: &DesktopAgentDisconnectContinuation,
) -> CoreResult<bool> {
    if let Some(reason) = retirement_blocked_reason(continuation) {
        update_desktop_state(runtime, |state| {
            state.block_desktop_agent_disconnect_retirement(reason)
        })?;
        finalize_blocked_disposition(runtime)?;
        return Ok(false);
    }
    if read_capability(runtime, continuation)?.is_none() {
        block_retirement_for_missing_capability(runtime)?;
        return Ok(false);
    }
    Ok(true)
}

fn required_capability<'a>(
    lease: &'a CommandLease<'_>,
) -> CoreResult<(&'a str, chrono::DateTime<Utc>)> {
    let capability = lease.disconnect_completion_capability.ok_or_else(|| {
        DesktopError::InvalidState(
            "desktop-agent Disconnect claim has no completion capability".to_string(),
        )
    })?;
    validate_disconnect_completion_capability(
        DesktopAgentCommandKind::Disconnect,
        Some(capability),
    )?;
    let expiry = lease.disconnect_completion_expires_at.ok_or_else(|| {
        DesktopError::InvalidState(
            "desktop-agent Disconnect claim has no completion deadline".to_string(),
        )
    })?;
    let now = Utc::now();
    if lease.expires_at <= now {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect claim lease is already expired".to_string(),
        ));
    }
    if expiry <= now {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect completion deadline is already expired".to_string(),
        ));
    }
    Ok((capability, expiry))
}

/// Reject an already-invalid broker command before it can request cancellation
/// from a live user sync. Admission is repeated under publication ownership
/// after the sync stops because its session and deadlines may change meanwhile.
fn preflight_disconnect_admission(runtime: &Runtime, lease: &CommandLease<'_>) -> CoreResult<()> {
    bound_agent_owner_session(runtime)?;
    current_agent_assertion(runtime)?;
    runtime
        .coordinator
        .snapshot()
        .desktop_agent_control
        .next_event_sequence(lease.command_id)?;
    required_capability(lease)?;
    Ok(())
}

async fn retire_remote(runtime: &Runtime) -> CoreResult<Retirement> {
    let continuation = pending_retiring_continuation(runtime)?;
    if let Some(reason) = retirement_blocked_reason(&continuation) {
        update_desktop_state(runtime, |state| {
            state.block_desktop_agent_disconnect_retirement(reason)
        })?;
        finalize_blocked_disposition(runtime)?;
        return Ok(Retirement::Blocked);
    }
    let capability = match read_capability(runtime, &continuation)? {
        Some(capability) => capability,
        None => {
            block_retirement_for_missing_capability(runtime)?;
            return Ok(Retirement::Blocked);
        }
    };
    let assertion = continuation.retire_assertion.as_ref().ok_or_else(|| {
        DesktopError::InvalidState(
            "desktop-agent Disconnect retirement has no persisted assertion".to_string(),
        )
    })?;
    match DriveHttpClient::new(&continuation.canonical_server_origin)?
        .retire_desktop_agent_disconnect(
            &capability,
            &continuation.command_id,
            &continuation.lease_id,
            assertion,
        )
        .await
    {
        Ok(()) => {
            mark_remote_retirement(runtime, &continuation.bound_owner_session)?;
            Ok(Retirement::Retired)
        }
        Err(DesktopAgentDisconnectTransportError::CancellationRequested) => {
            // Cancellation won before retirement admission. Reserve the exact
            // normal-device-bearer terminal in the same durable write as the
            // retained assertion, so restart retry cannot lose it.
            update_desktop_state(runtime, |state| {
                state.reserve_desktop_agent_disconnect_retirement_cancellation(Utc::now())
            })?;
            Ok(Retirement::CancelledBeforeAdmission)
        }
        Err(error) => {
            if let Some(reason) = blocked_reason(&error) {
                update_desktop_state(runtime, |state| {
                    state.block_desktop_agent_disconnect_retirement(reason)
                })?;
                finalize_blocked_disposition(runtime)?;
                return Ok(Retirement::Blocked);
            }
            Err(error.into_core_error())
        }
    }
}

async fn complete_cancelled_retirement(runtime: &Runtime) -> CoreResult<Execution> {
    let continuation = pending_cancelled_continuation(runtime)?;
    if cancelled_retirement_terminal_is_accepted(runtime, &continuation)? {
        finalize_cancelled_retirement(runtime)?;
        return Ok(Execution::Cancelled);
    }
    if let Some(reason) = retirement_blocked_reason(&continuation) {
        update_desktop_state(runtime, |state| {
            state.block_desktop_agent_disconnect_retirement(reason)
        })?;
        finalize_blocked_disposition(runtime)?;
        return Ok(Execution::Blocked);
    }
    let (retry, assertion) = cancelled_retirement_terminal(runtime, &continuation)?;
    let (_, device_credential) = crate::application::desktop_agent::device_credential(runtime)?;
    DriveHttpClient::new(&continuation.canonical_server_origin)?
        .report_desktop_agent_terminal(
            &device_credential,
            DesktopAgentTerminalReport {
                command_id: &retry.command_id,
                lease_id: &retry.lease_id,
                event_sequence: retry.event_sequence,
                assertion: &assertion,
                status: retry.terminal_status,
                terminal_code: retry.terminal_code,
                result_code: retry.result_code,
                result: retry.result.as_ref(),
            },
        )
        .await?;
    update_desktop_state(runtime, |state| {
        state
            .desktop_agent_control
            .mark_terminal_reported(&retry.command_id, Utc::now())
    })?;
    finalize_cancelled_retirement(runtime)?;
    Ok(Execution::Cancelled)
}

fn pending_retiring_continuation(
    runtime: &Runtime,
) -> CoreResult<DesktopAgentDisconnectContinuation> {
    let continuation = runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect retirement continuation is unavailable".to_string(),
            )
        })?;
    if continuation.phase != DesktopAgentDisconnectPhase::RetiringRemote {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect retirement is not pending".to_string(),
        ));
    }
    continuation.validate()?;
    Ok(continuation)
}

fn mark_remote_retirement(
    runtime: &Runtime,
    bound_owner_session: &Option<RemoteSessionRecord>,
) -> CoreResult<()> {
    let bound_owner_session = bound_owner_session.as_ref().ok_or_else(|| {
        DesktopError::InvalidState(
            "desktop-agent Disconnect retirement has no bound session locator".to_string(),
        )
    })?;
    update_desktop_state(runtime, |state| {
        state.mark_desktop_agent_disconnect_retired()?;
        state.remove_remote_session_record(bound_owner_session);
        state
            .pending_disconnect_cleanup_mut()
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent Disconnect cleanup intent disappeared after retirement"
                        .to_string(),
                )
            })?
            .confirm_remote_retirement();
        *state = state.clone().into_disconnected(Utc::now());
        Ok(())
    })?;
    *runtime.session.lock().expect("session lock") = None;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    invalidate_pending_confirmation(runtime);
    Ok(())
}

async fn complete_after_retirement(runtime: &Runtime) -> CoreResult<Execution> {
    let continuation = runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect completion disappeared before reporting".to_string(),
            )
        })?;
    if continuation.phase == DesktopAgentDisconnectPhase::LocalCleanup {
        complete_agent_disconnect_local_cleanup(runtime)?;
    }
    let continuation = runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect completion disappeared after local cleanup".to_string(),
            )
        })?;
    if continuation.phase == DesktopAgentDisconnectPhase::TerminalAccepted {
        return finalize_accepted_terminal(runtime);
    }
    if continuation.phase != DesktopAgentDisconnectPhase::Reporting {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect completion has no reportable continuation".to_string(),
        ));
    }
    if disconnect_deadline_reached(&continuation) {
        block_completion_after_deadline(runtime)?;
        return Ok(Execution::Blocked);
    }
    let capability = match read_capability(runtime, &continuation)? {
        Some(capability) => capability,
        None => {
            block_completion_for_missing_capability(runtime)?;
            return Ok(Execution::Blocked);
        }
    };
    let client = DriveHttpClient::new(&continuation.canonical_server_origin)?;
    match client
        .complete_desktop_agent_disconnect(
            &capability,
            &continuation.command_id,
            &continuation.lease_id,
            continuation.completion_event_sequence,
            false,
        )
        .await
    {
        Ok(()) => accept_terminal(runtime, DesktopAgentDisconnectTerminalReceipt::Completed),
        Err(DesktopAgentDisconnectTransportError::CancellationRequested) => {
            complete_cancelled_terminal(runtime, &continuation, &capability, &client).await
        }
        Err(error) => {
            if let Some(reason) = blocked_reason(&error) {
                update_desktop_state(runtime, |state| {
                    state.block_desktop_agent_disconnect_completion(reason)
                })?;
                finalize_blocked_disposition(runtime)?;
                return Ok(Execution::Blocked);
            }
            Err(error.into_core_error())
        }
    }
}

async fn complete_cancelled_terminal(
    runtime: &Runtime,
    continuation: &DesktopAgentDisconnectContinuation,
    capability: &str,
    client: &DriveHttpClient,
) -> CoreResult<Execution> {
    match client
        .complete_desktop_agent_disconnect(
            capability,
            &continuation.command_id,
            &continuation.lease_id,
            continuation.completion_event_sequence,
            true,
        )
        .await
    {
        Ok(()) => accept_terminal(runtime, DesktopAgentDisconnectTerminalReceipt::Cancelled),
        Err(error) => {
            if let Some(reason) = blocked_reason(&error) {
                update_desktop_state(runtime, |state| {
                    state.block_desktop_agent_disconnect_completion(reason)
                })?;
                finalize_blocked_disposition(runtime)?;
                return Ok(Execution::Blocked);
            }
            Err(error.into_core_error())
        }
    }
}

fn accept_terminal(
    runtime: &Runtime,
    receipt: DesktopAgentDisconnectTerminalReceipt,
) -> CoreResult<Execution> {
    // The server's 204 is durable before this receipt. A process crash after
    // the receipt save may repeat only local capability/control cleanup.
    update_desktop_state(runtime, |state| {
        state.record_desktop_agent_disconnect_terminal(receipt)
    })?;
    finalize_accepted_terminal(runtime)
}

fn finalize_accepted_terminal(runtime: &Runtime) -> CoreResult<Execution> {
    let continuation = runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect terminal receipt is unavailable".to_string(),
            )
        })?;
    if continuation.phase != DesktopAgentDisconnectPhase::TerminalAccepted {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect terminal receipt is not accepted".to_string(),
        ));
    }
    let receipt = continuation.terminal_receipt.ok_or_else(|| {
        DesktopError::InvalidState(
            "desktop-agent Disconnect terminal has no fixed receipt".to_string(),
        )
    })?;
    remove_exact_agent_credential(
        runtime.platform.desktop_agent_disconnect_credentials(),
        &desktop_agent_disconnect_credential_key(
            &continuation.canonical_server_origin,
            &continuation.command_id,
        ),
    )?;
    update_desktop_state(runtime, |state| state.finish_desktop_agent_disconnect())?;
    Ok(match receipt {
        DesktopAgentDisconnectTerminalReceipt::Completed => Execution::Completed,
        DesktopAgentDisconnectTerminalReceipt::Cancelled => Execution::Cancelled,
    })
}

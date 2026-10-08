//! Capability cleanup and durable disposition after Disconnect cannot finish.

use chrono::Utc;
use shellx_drive_desktop_core::{
    desktop_agent_disconnect_credential_key, validate_disconnect_completion_capability,
    DesktopAgentCommandKind, DesktopAgentDisconnectBlockedReason,
    DesktopAgentDisconnectContinuation, DesktopAgentDisconnectTransportError, DesktopError,
    Result as CoreResult,
};

use crate::application::desktop_agent::{remove_exact_agent_credential, update_desktop_state};

use super::Runtime;

#[cfg(test)]
#[path = "disposition_tests.rs"]
mod tests;

pub(super) fn disconnect_deadline_reached(
    continuation: &DesktopAgentDisconnectContinuation,
) -> bool {
    Utc::now() >= continuation.completion_expires_at
}

pub(super) fn block_completion_after_deadline(runtime: &Runtime) -> CoreResult<()> {
    update_desktop_state(runtime, |state| {
        state.block_desktop_agent_disconnect_completion(
            DesktopAgentDisconnectBlockedReason::CapabilityExpired,
        )
    })?;
    finalize_blocked_disposition(runtime)
}

/// The normal device-bearer retirement and pre-admission cancellation terminal
/// must not be retried after their original claim lease. Legacy persisted
/// continuations lack this field, so they are conservatively blocked rather
/// than guessing a renewed lease.
pub(super) fn retirement_blocked_reason(
    continuation: &DesktopAgentDisconnectContinuation,
) -> Option<DesktopAgentDisconnectBlockedReason> {
    match continuation.retirement_expires_at {
        Some(expires_at) if Utc::now() >= expires_at => {
            Some(DesktopAgentDisconnectBlockedReason::CapabilityExpired)
        }
        Some(_) => None,
        None => Some(DesktopAgentDisconnectBlockedReason::CapabilityUnavailable),
    }
}

pub(super) fn block_retirement_for_missing_capability(runtime: &Runtime) -> CoreResult<()> {
    update_desktop_state(runtime, |state| {
        state.block_desktop_agent_disconnect_retirement(
            DesktopAgentDisconnectBlockedReason::CapabilityUnavailable,
        )
    })?;
    finalize_blocked_disposition(runtime)
}

pub(super) fn block_completion_for_missing_capability(runtime: &Runtime) -> CoreResult<()> {
    update_desktop_state(runtime, |state| {
        state.block_desktop_agent_disconnect_completion(
            DesktopAgentDisconnectBlockedReason::CapabilityUnavailable,
        )
    })?;
    finalize_blocked_disposition(runtime)
}

pub(super) fn read_capability(
    runtime: &Runtime,
    continuation: &DesktopAgentDisconnectContinuation,
) -> CoreResult<Option<String>> {
    let capability_key = desktop_agent_disconnect_credential_key(
        &continuation.canonical_server_origin,
        &continuation.command_id,
    );
    // Preserve provider failures for the pending-continuation retry loop. Only
    // an absent or malformed value proves that this capability cannot be used.
    let Some(capability) = runtime
        .platform
        .desktop_agent_disconnect_credentials()
        .get(&capability_key)?
    else {
        return Ok(None);
    };
    if validate_disconnect_completion_capability(
        DesktopAgentCommandKind::Disconnect,
        Some(&capability),
    )
    .is_err()
    {
        return Ok(None);
    }
    Ok(Some(capability))
}

pub(super) fn finalize_cancelled_retirement(runtime: &Runtime) -> CoreResult<()> {
    let continuation = runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect cancellation disposition is unavailable".to_string(),
            )
        })?;
    if continuation.phase
        != shellx_drive_desktop_core::DesktopAgentDisconnectPhase::RetirementCancelled
    {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect retirement cancellation is not pending".to_string(),
        ));
    }
    remove_exact_agent_credential(
        runtime.platform.desktop_agent_disconnect_credentials(),
        &desktop_agent_disconnect_credential_key(
            &continuation.canonical_server_origin,
            &continuation.command_id,
        ),
    )?;
    update_desktop_state(runtime, |state| {
        state.finish_desktop_agent_disconnect_retirement_cancellation()
    })
}

pub(super) fn finalize_blocked_disposition(runtime: &Runtime) -> CoreResult<()> {
    let continuation = runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect terminal disposition is unavailable".to_string(),
            )
        })?;
    remove_exact_agent_credential(
        runtime.platform.desktop_agent_disconnect_credentials(),
        &desktop_agent_disconnect_credential_key(
            &continuation.canonical_server_origin,
            &continuation.command_id,
        ),
    )?;
    update_desktop_state(runtime, |state| {
        state.archive_desktop_agent_disconnect_block()
    })
}

pub(super) fn blocked_reason(
    error: &DesktopAgentDisconnectTransportError,
) -> Option<DesktopAgentDisconnectBlockedReason> {
    match error {
        DesktopAgentDisconnectTransportError::CapabilityExpired => {
            Some(DesktopAgentDisconnectBlockedReason::CapabilityExpired)
        }
        DesktopAgentDisconnectTransportError::AuthorizationLost => {
            Some(DesktopAgentDisconnectBlockedReason::AuthorizationLost)
        }
        DesktopAgentDisconnectTransportError::Other(DesktopError::Server {
            status: 409, ..
        }) => Some(DesktopAgentDisconnectBlockedReason::BrokerConflict),
        _ => None,
    }
}

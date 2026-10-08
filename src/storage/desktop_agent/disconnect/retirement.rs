//! First admission and exact retry for the Disconnect self-retirement boundary.

use chrono::Utc;
use rusqlite::{params, TransactionBehavior};

use crate::{
    desktop_agent::{
        validate_disconnect_retirement_request, DesktopAgentCommandStatus, DesktopAgentDeviceState,
        DesktopAgentDisconnectRetirementRequest, DesktopAgentPhase,
    },
    error::{ApiError, ApiResult},
};

use super::{
    completion_for_capability_in_tx, ensure_completion_capability_live, ensure_disconnect_command,
    ensure_retirement_still_pending_in_tx, not_expired, CommandEvent, CompletionRecord, Storage,
};
use crate::storage::desktop_agent::{
    guards::{
        ensure_command_source_active_in_tx, ensure_device_live_for_owner_in_tx,
        recover_stale_leases_in_tx,
    },
    rows::load_command_row_for_device_in_tx,
};

impl Storage {
    pub fn begin_desktop_agent_disconnect_retirement(
        &self,
        command_id: &str,
        capability: &str,
        request: &DesktopAgentDisconnectRetirementRequest,
    ) -> ApiResult<()> {
        validate_disconnect_retirement_request(&request.lease_id, &request.assertion)?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let assertion_hash = assertion_witness(&request.assertion)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let completion = completion_for_capability_in_tx(&tx, command_id, capability)?;
        ensure_completion_capability_live(&completion, now)?;
        let command = load_command_row_for_device_in_tx(&tx, command_id, &completion.device_id)?
            .ok_or(ApiError::NotFound)?;
        if completion.retirement_authorized_at.is_some() {
            ensure_retirement_retry(
                &tx,
                &command,
                &completion,
                &request.lease_id,
                &assertion_hash,
            )?;
            tx.commit()?;
            return Ok(());
        }

        recover_stale_leases_in_tx(&tx, &completion.device_id, &now_text)?;
        let command = load_command_row_for_device_in_tx(&tx, command_id, &completion.device_id)?
            .ok_or(ApiError::NotFound)?;
        if command.status.is_terminal() || command.lease_id.as_deref() != Some(&request.lease_id) {
            // Recovery is a truthful terminalization, so retain it before
            // rejecting this admission. Nothing from retirement has run yet.
            tx.commit()?;
            return Err(ApiError::Conflict);
        }
        if command.status == DesktopAgentCommandStatus::CancelRequested {
            return Err(ApiError::DesktopAgentCancellationRequested);
        }
        ensure_disconnect_command(&command, &completion, &request.lease_id, now, false)?;
        ensure_live_lease(&command, now)?;
        admit_first_retirement(&tx, &command, &completion, request)?;

        let bound = tx.execute(
            "UPDATE desktop_agent_disconnect_completions
             SET retirement_authorized_at = ?1, retirement_assertion_hash = ?2
             WHERE command_id = ?3 AND retirement_authorized_at IS NULL
               AND retirement_assertion_hash IS NULL",
            params![&now_text, &assertion_hash, command_id],
        )?;
        if bound != 1 {
            return Err(ApiError::Conflict);
        }
        let frozen = tx.execute(
            "UPDATE desktop_agent_devices SET state = 'frozen', frozen_at = COALESCE(frozen_at, ?1)
             WHERE id = ?2 AND state = 'active'",
            params![&now_text, &completion.device_id],
        )?;
        if frozen != 1 {
            return Err(ApiError::Conflict);
        }
        let updated = tx.execute(
            "UPDATE desktop_agent_commands
             SET status = 'running', started_at = COALESCE(started_at, ?1),
                 lease_expires_at = ?2, lease_phase = 'disconnecting',
                 lease_progress_basis_points = NULL
             WHERE id = ?3 AND status IN ('acknowledged', 'running')",
            params![&now_text, &completion.expires_at, command_id],
        )?;
        if updated != 1 {
            return Err(ApiError::Conflict);
        }
        crate::storage::desktop_agent::guards::append_event_in_tx(
            &tx,
            command_id,
            &now_text,
            CommandEvent::phase(
                DesktopAgentCommandStatus::Running,
                DesktopAgentPhase::Disconnecting,
                None,
            ),
        )?;
        let revoked = tx.execute(
            "UPDATE auth_sessions SET revoked_at = ?1
             WHERE id = ?2 AND revoked_at IS NULL",
            params![&now_text, &completion.owner_session_id],
        )?;
        if revoked != 1 {
            return Err(ApiError::DesktopAgentDisconnectAuthorizationLost);
        }
        tx.commit()?;
        Ok(())
    }
}

fn admit_first_retirement(
    tx: &rusqlite::Transaction<'_>,
    command: &crate::storage::desktop_agent::rows::CommandRow,
    completion: &CompletionRecord,
    request: &DesktopAgentDisconnectRetirementRequest,
) -> ApiResult<()> {
    if !request.assertion.pending_disconnect_cleanup
        || request.assertion.candidate_recovery
        || request.assertion.pair_fingerprint != completion.pair_fingerprint
    {
        return Err(ApiError::Conflict);
    }
    let device =
        ensure_device_live_for_owner_in_tx(tx, &completion.device_id, &command.owner_account_id)
            .map_err(super::disconnect_authorization_error)?;
    if device.state != DesktopAgentDeviceState::Active || device.candidate_recovery {
        return Err(ApiError::DesktopAgentDisconnectAuthorizationLost);
    }
    ensure_command_source_active_in_tx(tx, command).map_err(super::disconnect_authorization_error)
}

fn ensure_retirement_retry(
    tx: &rusqlite::Transaction<'_>,
    command: &crate::storage::desktop_agent::rows::CommandRow,
    completion: &CompletionRecord,
    lease_id: &str,
    assertion_hash: &str,
) -> ApiResult<()> {
    if completion.retirement_assertion_hash.as_deref() != Some(assertion_hash) {
        return Err(ApiError::Conflict);
    }
    ensure_retirement_still_pending_in_tx(tx, command, completion)?;
    ensure_disconnect_command(command, completion, lease_id, Utc::now(), true)
}

fn ensure_live_lease(
    command: &crate::storage::desktop_agent::rows::CommandRow,
    now: chrono::DateTime<Utc>,
) -> ApiResult<()> {
    command
        .lease_expires_at
        .as_deref()
        .is_some_and(|expires_at| not_expired(expires_at, now))
        .then_some(())
        .ok_or(ApiError::Conflict)
}

fn assertion_witness(
    assertion: &crate::desktop_agent::DesktopAgentDeviceAssertion,
) -> ApiResult<String> {
    serde_json::to_string(assertion)
        .map(|serialized| crate::auth::token_hash(&serialized))
        .map_err(|_| ApiError::Validation("invalid_desktop_agent_state".to_string()))
}

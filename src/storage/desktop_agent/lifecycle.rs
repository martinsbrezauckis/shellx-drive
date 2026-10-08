use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential},
    desktop_agent::{
        validate_device_assertion, validate_lease_event, DesktopAgentAcknowledgeRequest,
        DesktopAgentClaimResponse, DesktopAgentCommand, DesktopAgentCommandPage,
        DesktopAgentCommandStatus, DesktopAgentDeviceAssertion, DesktopAgentLease,
        DesktopAgentPhase, DesktopAgentProgressRequest, DesktopAgentTerminalCode,
        DesktopAgentTerminalRequest, DESKTOP_AGENT_LEASE_SECONDS,
        DESKTOP_AGENT_RELAUNCH_GRACE_SECONDS,
    },
    error::{ApiError, ApiResult},
};

use super::{
    authorization,
    disconnect::issue_completion_capability_in_tx,
    guards::{
        append_event_in_tx, authenticate_device_in_tx, device_has_active_command_in_tx,
        device_id_for_credential_in_tx, ensure_command_source_active_in_tx, enum_db,
        expire_queued_commands_for_owner_in_tx, invalidate_device_commands_in_tx,
        recover_stale_leases_for_owner_in_tx, recover_stale_leases_in_tx,
        terminalize_command_in_tx, CommandEvent,
    },
    progress::validate_progress_phase_for_command,
    rows::{load_command_for_owner_in_tx, load_command_row_for_device_in_tx},
    terminal::{terminal_retry_matches, validate_terminal_request},
    Storage, DEFAULT_COMMAND_PAGE_LIMIT, MAX_COMMAND_PAGE_LIMIT,
};

mod claim;

impl Storage {
    pub fn get_desktop_agent_command(
        &self,
        command_id: &str,
        owner: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<DesktopAgentCommand> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, owner, source_credential)?;
        let (owner_account_id, _) = super::account_binding_in_tx(&tx, owner)?;
        let now = Utc::now().to_rfc3339();
        recover_stale_leases_for_owner_in_tx(&tx, &owner_account_id, &now)?;
        expire_queued_commands_for_owner_in_tx(&tx, &owner_account_id, &now)?;
        let command = load_command_for_owner_in_tx(&tx, command_id, &owner_account_id)?
            .ok_or(ApiError::NotFound)?;
        tx.commit()?;
        Ok(command)
    }

    pub fn list_desktop_agent_commands(
        &self,
        owner: &Actor,
        source_credential: &DriveCredential,
        requested_limit: Option<i64>,
        before: Option<&str>,
    ) -> ApiResult<DesktopAgentCommandPage> {
        let limit = requested_limit.unwrap_or(DEFAULT_COMMAND_PAGE_LIMIT);
        if !(1..=MAX_COMMAND_PAGE_LIMIT).contains(&limit) {
            return Err(ApiError::Validation(
                "invalid_desktop_agent_page".to_string(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, owner, source_credential)?;
        let (owner_account_id, _) = super::account_binding_in_tx(&tx, owner)?;
        let now = Utc::now().to_rfc3339();
        recover_stale_leases_for_owner_in_tx(&tx, &owner_account_id, &now)?;
        expire_queued_commands_for_owner_in_tx(&tx, &owner_account_id, &now)?;
        let cursor = match before {
            Some(before) => tx
                .query_row(
                    "SELECT created_at, id FROM desktop_agent_commands
                     WHERE id = ?1 AND owner_account_id = ?2",
                    params![before, &owner_account_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?,
            None => ("9999-12-31T23:59:59Z".to_string(), "~".to_string()),
        };
        let mut statement = tx.prepare(
            "SELECT id FROM desktop_agent_commands
             WHERE owner_account_id = ?1 AND (created_at < ?2 OR (created_at = ?2 AND id < ?3))
             ORDER BY created_at DESC, id DESC LIMIT ?4",
        )?;
        let ids = statement
            .query_map(
                params![&owner_account_id, &cursor.0, &cursor.1, limit + 1],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let has_next = ids.len() > limit as usize;
        let ids = ids.into_iter().take(limit as usize).collect::<Vec<_>>();
        let commands = ids
            .iter()
            .map(|id| {
                load_command_for_owner_in_tx(&tx, id, &owner_account_id)?.ok_or(ApiError::NotFound)
            })
            .collect::<ApiResult<Vec<_>>>()?;
        let next_cursor = has_next.then(|| ids.last().cloned()).flatten();
        tx.commit()?;
        Ok(DesktopAgentCommandPage {
            commands,
            next_cursor,
        })
    }

    pub fn cancel_desktop_agent_command(
        &self,
        command_id: &str,
        owner: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<DesktopAgentCommand> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, owner, source_credential)?;
        let (owner_account_id, _) = super::account_binding_in_tx(&tx, owner)?;
        let command = load_command_row_for_device_or_owner(&tx, command_id, &owner_account_id)?
            .ok_or(ApiError::NotFound)?;
        match command.status {
            DesktopAgentCommandStatus::Queued => {
                terminalize_command_in_tx(
                    &tx,
                    command_id,
                    &now,
                    CommandEvent::terminal(
                        DesktopAgentCommandStatus::Cancelled,
                        DesktopAgentTerminalCode::CancelledBeforeStart,
                        None,
                        None,
                    ),
                )?;
            }
            DesktopAgentCommandStatus::Leased
            | DesktopAgentCommandStatus::Acknowledged
            | DesktopAgentCommandStatus::Running
            | DesktopAgentCommandStatus::RelaunchPending => {
                tx.execute(
                    "UPDATE desktop_agent_commands SET status = 'cancel_requested'
                     WHERE id = ?1",
                    [command_id],
                )?;
                append_event_in_tx(
                    &tx,
                    command_id,
                    &now,
                    CommandEvent::state(DesktopAgentCommandStatus::CancelRequested),
                )?;
            }
            _ => {}
        }
        let command = load_command_for_owner_in_tx(&tx, command_id, &owner_account_id)?
            .ok_or(ApiError::NotFound)?;
        tx.commit()?;
        Ok(command)
    }

    pub fn claim_desktop_agent_command(
        &self,
        device_id: &str,
        device_credential: &str,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> ApiResult<DesktopAgentClaimResponse> {
        validate_device_assertion(assertion)?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device = authenticate_device_in_tx(&tx, device_id, device_credential, assertion)?;
        if assertion.pending_disconnect_cleanup {
            freeze_device_in_tx(&tx, &device.id, &now_text)?;
            tx.commit()?;
            return Ok(DesktopAgentClaimResponse { claim: None });
        }
        if device.state != crate::desktop_agent::DesktopAgentDeviceState::Active {
            tx.commit()?;
            return Ok(DesktopAgentClaimResponse { claim: None });
        }
        recover_stale_leases_in_tx(&tx, &device.id, &now_text)?;
        expire_queued_commands_in_tx(&tx, &device.id, &now_text)?;
        if assertion.candidate_recovery {
            reject_queued_commands_in_tx(
                &tx,
                &device.id,
                &now_text,
                DesktopAgentTerminalCode::CandidateRecovery,
            )?;
            tx.commit()?;
            return Ok(DesktopAgentClaimResponse { claim: None });
        }
        if device_has_active_command_in_tx(&tx, &device.id)? {
            tx.commit()?;
            return Ok(DesktopAgentClaimResponse { claim: None });
        }
        for _ in 0..16 {
            let Some(command) = claim::next_queued_command_in_tx(&tx, &device.id)? else {
                tx.commit()?;
                return Ok(DesktopAgentClaimResponse { claim: None });
            };
            if claim::reject_unclaimable_command_in_tx(&tx, &command, &now_text)? {
                continue;
            }
            if ensure_command_source_active_in_tx(&tx, &command).is_err() {
                terminalize_command_in_tx(
                    &tx,
                    &command.id,
                    &now_text,
                    CommandEvent::terminal(
                        DesktopAgentCommandStatus::Interrupted,
                        DesktopAgentTerminalCode::AuthorizationLost,
                        None,
                        None,
                    ),
                )?;
                continue;
            }
            let lease_id = format!("lease-{}", Uuid::now_v7());
            let lease_expires_at =
                lease_expiry_for_command(&command, now, DESKTOP_AGENT_LEASE_SECONDS)?;
            let updated = tx.execute(
                "UPDATE desktop_agent_commands
                 SET status = 'leased', lease_id = ?1, lease_expires_at = ?2,
                     lease_event_sequence = 0, lease_phase = NULL,
                     lease_progress_basis_points = NULL
                 WHERE id = ?3 AND status = 'queued'",
                params![&lease_id, &lease_expires_at, &command.id],
            )?;
            if updated != 1 {
                continue;
            }
            append_event_in_tx(
                &tx,
                &command.id,
                &now_text,
                CommandEvent::state(DesktopAgentCommandStatus::Leased),
            )?;
            let payload = command.payload.wire_payload();
            let disconnect_completion_capability =
                issue_completion_capability_in_tx(&tx, &command, &device, &lease_id, assertion)?;
            let disconnect_completion_expires_at = disconnect_completion_capability
                .as_ref()
                .map(|_| command.expires_at.clone());
            tx.commit()?;
            return Ok(DesktopAgentClaimResponse {
                claim: Some(DesktopAgentLease {
                    command_id: command.id,
                    lease_id,
                    lease_expires_at,
                    kind: command.kind,
                    payload,
                    disconnect_completion_capability,
                    disconnect_completion_expires_at,
                }),
            });
        }
        tx.commit()?;
        Ok(DesktopAgentClaimResponse { claim: None })
    }

    pub fn heartbeat_desktop_agent_device(
        &self,
        device_id: &str,
        device_credential: &str,
        assertion: &DesktopAgentDeviceAssertion,
    ) -> ApiResult<()> {
        validate_device_assertion(assertion)?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device = authenticate_device_in_tx(&tx, device_id, device_credential, assertion)?;
        if assertion.pending_disconnect_cleanup {
            freeze_device_in_tx(&tx, &device.id, &now_text)?;
        } else if device.state == crate::desktop_agent::DesktopAgentDeviceState::Active {
            tx.execute(
                "UPDATE desktop_agent_devices SET last_ready_at = ?1 WHERE id = ?2",
                params![&now_text, &device.id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn acknowledge_desktop_agent_command(
        &self,
        command_id: &str,
        device_credential: &str,
        request: &DesktopAgentAcknowledgeRequest,
    ) -> ApiResult<()> {
        validate_device_assertion(&request.assertion)?;
        validate_lease_event(&request.lease_id, request.event_sequence)?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device_id = device_id_for_credential_in_tx(&tx, device_credential)?;
        let device =
            authenticate_device_in_tx(&tx, &device_id, device_credential, &request.assertion)?;
        if request.assertion.pending_disconnect_cleanup {
            freeze_device_in_tx(&tx, &device.id, &now_text)?;
            tx.commit()?;
            return Err(ApiError::Conflict);
        }
        ensure_active_device(&device)?;
        let command = load_command_row_for_device_in_tx(&tx, command_id, &device.id)?
            .ok_or(ApiError::NotFound)?;
        if command.status == DesktopAgentCommandStatus::Acknowledged
            && command.lease_id.as_deref() == Some(&request.lease_id)
            && command.lease_event_sequence == Some(request.event_sequence)
        {
            if ensure_command_source_active_in_tx(&tx, &command).is_err() {
                terminalize_command_in_tx(
                    &tx,
                    command_id,
                    &now_text,
                    CommandEvent::terminal(
                        DesktopAgentCommandStatus::Interrupted,
                        DesktopAgentTerminalCode::AuthorizationLost,
                        None,
                        None,
                    ),
                )?;
                tx.commit()?;
                return Err(ApiError::Forbidden);
            }
            tx.commit()?;
            return Ok(());
        }
        ensure_current_lease(
            &command,
            &request.lease_id,
            request.event_sequence,
            now,
            false,
        )?;
        if request.assertion.candidate_recovery {
            terminalize_command_in_tx(
                &tx,
                command_id,
                &now_text,
                CommandEvent::terminal(
                    DesktopAgentCommandStatus::Interrupted,
                    DesktopAgentTerminalCode::CandidateRecovery,
                    None,
                    None,
                ),
            )?;
            tx.commit()?;
            return Err(ApiError::Conflict);
        }
        if ensure_command_source_active_in_tx(&tx, &command).is_err() {
            terminalize_command_in_tx(
                &tx,
                command_id,
                &now_text,
                CommandEvent::terminal(
                    DesktopAgentCommandStatus::Interrupted,
                    DesktopAgentTerminalCode::AuthorizationLost,
                    None,
                    None,
                ),
            )?;
            tx.commit()?;
            return Err(ApiError::Forbidden);
        }
        tx.execute(
            "UPDATE desktop_agent_commands
             SET status = 'acknowledged', accepted_at = ?1, lease_event_sequence = ?2
             WHERE id = ?3",
            params![&now_text, request.event_sequence, command_id],
        )?;
        append_event_in_tx(
            &tx,
            command_id,
            &now_text,
            CommandEvent::phase(
                DesktopAgentCommandStatus::Acknowledged,
                DesktopAgentPhase::Accepted,
                None,
            ),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn progress_desktop_agent_command(
        &self,
        command_id: &str,
        device_credential: &str,
        request: &DesktopAgentProgressRequest,
    ) -> ApiResult<()> {
        validate_device_assertion(&request.assertion)?;
        validate_lease_event(&request.lease_id, request.event_sequence)?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device_id = device_id_for_credential_in_tx(&tx, device_credential)?;
        let device =
            authenticate_device_in_tx(&tx, &device_id, device_credential, &request.assertion)?;
        if request.assertion.pending_disconnect_cleanup {
            freeze_device_in_tx(&tx, &device.id, &now_text)?;
            tx.commit()?;
            return Err(ApiError::Conflict);
        }
        ensure_active_device(&device)?;
        let command = load_command_row_for_device_in_tx(&tx, command_id, &device.id)?
            .ok_or(ApiError::NotFound)?;
        validate_progress_phase_for_command(&tx, &command, request.phase)?;
        if command.status == DesktopAgentCommandStatus::CancelRequested {
            return Err(ApiError::DesktopAgentCancellationRequested);
        }
        let status = if request.phase == DesktopAgentPhase::RelaunchPending {
            DesktopAgentCommandStatus::RelaunchPending
        } else {
            DesktopAgentCommandStatus::Running
        };
        if !request.assertion.candidate_recovery
            && progress_retry_matches(&tx, &command, command_id, request, status)?
        {
            if ensure_command_source_active_in_tx(&tx, &command).is_err() {
                terminalize_command_in_tx(
                    &tx,
                    command_id,
                    &now_text,
                    CommandEvent::terminal(
                        DesktopAgentCommandStatus::Interrupted,
                        DesktopAgentTerminalCode::AuthorizationLost,
                        None,
                        None,
                    ),
                )?;
                tx.commit()?;
                return Err(ApiError::Forbidden);
            }
            tx.commit()?;
            return Ok(());
        }
        ensure_current_lease(
            &command,
            &request.lease_id,
            request.event_sequence,
            now,
            false,
        )?;
        if request.assertion.candidate_recovery {
            terminalize_command_in_tx(
                &tx,
                command_id,
                &now_text,
                CommandEvent::terminal(
                    DesktopAgentCommandStatus::Interrupted,
                    DesktopAgentTerminalCode::CandidateRecovery,
                    None,
                    None,
                ),
            )?;
            tx.commit()?;
            return Err(ApiError::Conflict);
        }
        if ensure_command_source_active_in_tx(&tx, &command).is_err() {
            terminalize_command_in_tx(
                &tx,
                command_id,
                &now_text,
                CommandEvent::terminal(
                    DesktopAgentCommandStatus::Interrupted,
                    DesktopAgentTerminalCode::AuthorizationLost,
                    None,
                    None,
                ),
            )?;
            tx.commit()?;
            return Err(ApiError::Forbidden);
        }
        let lease_seconds = if request.phase == DesktopAgentPhase::RelaunchPending {
            DESKTOP_AGENT_RELAUNCH_GRACE_SECONDS
        } else {
            DESKTOP_AGENT_LEASE_SECONDS
        };
        let lease_expires_at = lease_expiry_for_command(&command, now, lease_seconds)?;
        tx.execute(
            "UPDATE desktop_agent_commands SET status = ?1, started_at = COALESCE(started_at, ?2),
             lease_event_sequence = ?3, lease_expires_at = ?4, lease_phase = ?5,
             lease_progress_basis_points = ?6 WHERE id = ?7",
            params![
                enum_db(status)?,
                &now_text,
                request.event_sequence,
                &lease_expires_at,
                enum_db(request.phase)?,
                request.progress_basis_points.map(i64::from),
                command_id
            ],
        )?;
        append_event_in_tx(
            &tx,
            command_id,
            &now_text,
            CommandEvent::phase(status, request.phase, request.progress_basis_points),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn terminal_desktop_agent_command(
        &self,
        command_id: &str,
        device_credential: &str,
        request: &DesktopAgentTerminalRequest,
    ) -> ApiResult<()> {
        validate_device_assertion(&request.assertion)?;
        validate_lease_event(&request.lease_id, request.event_sequence)?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device_id = device_id_for_credential_in_tx(&tx, device_credential)?;
        let device =
            authenticate_device_in_tx(&tx, &device_id, device_credential, &request.assertion)?;
        let command = load_command_row_for_device_in_tx(&tx, command_id, &device.id)?
            .ok_or(ApiError::NotFound)?;
        let cancellation_terminal = request.status
            == crate::desktop_agent::DesktopAgentTerminalStatus::Interrupted
            && request.terminal_code == DesktopAgentTerminalCode::CancellationRequested
            && request.result_code.is_none()
            && request.result.is_none();
        ensure_active_device(&device)?;
        if terminal_retry_matches(&tx, &command, command_id, request)? {
            if ensure_command_source_active_in_tx(&tx, &command).is_err() {
                tx.commit()?;
                return Err(ApiError::Forbidden);
            }
            tx.commit()?;
            return Ok(());
        }
        if request.assertion.pending_disconnect_cleanup
            && !(command.kind == crate::desktop_agent::DesktopAgentCommandKind::Disconnect
                && command.status == DesktopAgentCommandStatus::CancelRequested
                && cancellation_terminal)
        {
            freeze_device_in_tx(&tx, &device.id, &now_text)?;
            tx.commit()?;
            return Err(ApiError::Conflict);
        }
        if command.status == DesktopAgentCommandStatus::CancelRequested && !cancellation_terminal {
            return Err(ApiError::DesktopAgentCancellationRequested);
        }
        if request.terminal_code == DesktopAgentTerminalCode::CancellationRequested
            && command.status != DesktopAgentCommandStatus::CancelRequested
        {
            return Err(ApiError::Validation(
                "invalid_desktop_agent_terminal".to_string(),
            ));
        }
        validate_terminal_request(&command, request)?;
        ensure_current_lease(
            &command,
            &request.lease_id,
            request.event_sequence,
            now,
            true,
        )?;
        if request.assertion.candidate_recovery {
            terminalize_command_in_tx(
                &tx,
                command_id,
                &now_text,
                CommandEvent::terminal(
                    DesktopAgentCommandStatus::Interrupted,
                    DesktopAgentTerminalCode::CandidateRecovery,
                    None,
                    None,
                ),
            )?;
            tx.commit()?;
            return Err(ApiError::Conflict);
        }
        if ensure_command_source_active_in_tx(&tx, &command).is_err() {
            terminalize_command_in_tx(
                &tx,
                command_id,
                &now_text,
                CommandEvent::terminal(
                    DesktopAgentCommandStatus::Interrupted,
                    DesktopAgentTerminalCode::AuthorizationLost,
                    None,
                    None,
                ),
            )?;
            tx.commit()?;
            return Err(ApiError::Forbidden);
        }
        terminalize_command_in_tx(
            &tx,
            command_id,
            &now_text,
            CommandEvent::terminal(
                request.status.into(),
                request.terminal_code,
                request.result_code,
                request.result.clone(),
            ),
        )?;
        tx.execute(
            "UPDATE desktop_agent_commands SET terminal_event_sequence = ?1 WHERE id = ?2",
            params![request.event_sequence, command_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn load_command_row_for_device_or_owner(
    tx: &rusqlite::Transaction<'_>,
    command_id: &str,
    owner_account_id: &str,
) -> ApiResult<Option<super::rows::CommandRow>> {
    super::rows::load_command_row_in_tx(tx, command_id, Some(owner_account_id))
}

fn freeze_device_in_tx(
    tx: &rusqlite::Transaction<'_>,
    device_id: &str,
    now: &str,
) -> ApiResult<()> {
    tx.execute(
        "UPDATE desktop_agent_devices
         SET state = 'frozen', frozen_at = COALESCE(frozen_at, ?1) WHERE id = ?2 AND state = 'active'",
        params![now, device_id],
    )?;
    invalidate_device_commands_in_tx(
        tx,
        device_id,
        now,
        DesktopAgentTerminalCode::PendingDisconnect,
    )
}

fn ensure_active_device(device: &super::guards::DeviceGuard) -> ApiResult<()> {
    if device.state == crate::desktop_agent::DesktopAgentDeviceState::Active {
        Ok(())
    } else {
        Err(ApiError::Conflict)
    }
}

fn ensure_current_lease(
    command: &super::rows::CommandRow,
    lease_id: &str,
    event_sequence: i64,
    now: DateTime<Utc>,
    allow_cancel_requested: bool,
) -> ApiResult<()> {
    let lease_matches = command.lease_id.as_deref() == Some(lease_id)
        && command
            .lease_event_sequence
            .is_some_and(|previous| event_sequence > previous);
    let status_allows_event = matches!(
        command.status,
        DesktopAgentCommandStatus::Leased
            | DesktopAgentCommandStatus::Acknowledged
            | DesktopAgentCommandStatus::Running
            | DesktopAgentCommandStatus::RelaunchPending
    ) || (allow_cancel_requested
        && command.status == DesktopAgentCommandStatus::CancelRequested);
    if !lease_matches || !status_allows_event {
        return Err(ApiError::Conflict);
    }
    let unexpired = command
        .lease_expires_at
        .as_deref()
        .and_then(parse_rfc3339_utc)
        .is_some_and(|expires_at| expires_at > now)
        && parse_rfc3339_utc(&command.expires_at).is_some_and(|expires_at| expires_at > now);
    if !unexpired {
        return Err(ApiError::Conflict);
    }
    Ok(())
}

fn lease_expiry_for_command(
    command: &super::rows::CommandRow,
    now: DateTime<Utc>,
    lease_seconds: i64,
) -> ApiResult<String> {
    let deadline = parse_rfc3339_utc(&command.expires_at).ok_or(ApiError::Conflict)?;
    if deadline <= now {
        return Err(ApiError::Conflict);
    }
    Ok(std::cmp::min(deadline, now + Duration::seconds(lease_seconds)).to_rfc3339())
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn progress_retry_matches(
    tx: &rusqlite::Transaction<'_>,
    command: &super::rows::CommandRow,
    command_id: &str,
    request: &DesktopAgentProgressRequest,
    status: DesktopAgentCommandStatus,
) -> ApiResult<bool> {
    if command.status != status
        || command.lease_id.as_deref() != Some(&request.lease_id)
        || command.lease_event_sequence != Some(request.event_sequence)
    {
        return Ok(false);
    }
    let (phase, progress) = tx.query_row(
        "SELECT lease_phase, lease_progress_basis_points
         FROM desktop_agent_commands WHERE id = ?1",
        [command_id],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<i64>>(1)?,
            ))
        },
    )?;
    Ok(phase.as_deref() == Some(&enum_db(request.phase)?)
        && progress == request.progress_basis_points.map(i64::from))
}

fn expire_queued_commands_in_tx(
    tx: &rusqlite::Transaction<'_>,
    device_id: &str,
    now: &str,
) -> ApiResult<()> {
    let mut statement = tx.prepare(
        "SELECT id FROM desktop_agent_commands WHERE device_id = ?1 AND status = 'queued'
         AND julianday(expires_at) <= julianday(?2) ORDER BY expires_at ASC LIMIT 32",
    )?;
    let ids = statement
        .query_map(params![device_id, now], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for id in ids {
        terminalize_command_in_tx(
            tx,
            &id,
            now,
            CommandEvent::terminal(
                DesktopAgentCommandStatus::Expired,
                DesktopAgentTerminalCode::LeaseExpired,
                None,
                None,
            ),
        )?;
    }
    Ok(())
}
fn reject_queued_commands_in_tx(
    tx: &rusqlite::Transaction<'_>,
    device_id: &str,
    now: &str,
    code: DesktopAgentTerminalCode,
) -> ApiResult<()> {
    let mut statement = tx.prepare(
        "SELECT id FROM desktop_agent_commands WHERE device_id = ?1 AND status = 'queued'
         ORDER BY created_at ASC LIMIT 32",
    )?;
    let ids = statement
        .query_map([device_id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for id in ids {
        terminalize_command_in_tx(
            tx,
            &id,
            now,
            CommandEvent::terminal(DesktopAgentCommandStatus::Rejected, code, None, None),
        )?;
    }
    Ok(())
}

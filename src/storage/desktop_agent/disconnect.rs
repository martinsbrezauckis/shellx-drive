//! One narrow terminal path for a Disconnect that has deliberately retired
//! its own bound local session before local cleanup can finish.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, Transaction};

use crate::{
    auth::{random_secret_token, token_hash},
    desktop_agent::{
        validate_disconnect_completion_request, DesktopAgentCommandKind, DesktopAgentCommandStatus,
        DesktopAgentDeviceAssertion, DesktopAgentDisconnectCompletionRequest,
        DesktopAgentResultCode, DesktopAgentResultPayload, DesktopAgentTerminalCode,
    },
    error::{ApiError, ApiResult},
};

use super::{
    guards::{ensure_command_source_active_in_tx, terminalize_command_in_tx, CommandEvent},
    rows::{load_command_row_for_device_in_tx, CommandRow},
    DeviceGuard, Storage,
};

mod retirement;

pub(super) const DISCONNECT_COMPLETION_SECRET_PREFIX: &str = "sxd_disconnect_";

#[derive(Clone)]
pub(super) struct CompletionRecord {
    pub(super) device_id: String,
    pub(super) owner_session_id: String,
    pub(super) owner_security_version: i64,
    pub(super) lease_id: String,
    pub(super) pair_fingerprint: String,
    pub(super) retirement_assertion_hash: Option<String>,
    pub(super) expires_at: String,
    pub(super) retirement_authorized_at: Option<String>,
    pub(super) completed_at: Option<String>,
}

struct DisconnectTerminal<'a> {
    event_sequence: i64,
    at: &'a str,
    status: DesktopAgentCommandStatus,
    terminal_code: DesktopAgentTerminalCode,
    result: Option<DesktopAgentResultPayload>,
}

pub(super) fn issue_completion_capability_in_tx(
    tx: &Transaction<'_>,
    command: &CommandRow,
    device: &DeviceGuard,
    lease_id: &str,
    assertion: &DesktopAgentDeviceAssertion,
) -> ApiResult<Option<String>> {
    if command.kind != DesktopAgentCommandKind::Disconnect {
        return Ok(None);
    }
    let owner_session_id = tx.query_row(
        "SELECT owner_session_id FROM desktop_agent_devices WHERE id = ?1",
        [&device.id],
        |row| row.get::<_, String>(0),
    )?;
    let capability = format!(
        "{DISCONNECT_COMPLETION_SECRET_PREFIX}{}",
        random_secret_token()
    );
    tx.execute(
        "INSERT INTO desktop_agent_disconnect_completions (
             command_id, device_id, owner_session_id, owner_security_version, lease_id,
             pair_fingerprint, capability_hash, retirement_assertion_hash, expires_at,
             retirement_authorized_at, completed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, NULL, NULL)
         ON CONFLICT(command_id) DO UPDATE SET
             device_id = excluded.device_id, owner_session_id = excluded.owner_session_id,
             owner_security_version = excluded.owner_security_version, lease_id = excluded.lease_id,
             pair_fingerprint = excluded.pair_fingerprint, capability_hash = excluded.capability_hash,
             retirement_assertion_hash = NULL, expires_at = excluded.expires_at,
             retirement_authorized_at = NULL, completed_at = NULL",
        params![
            &command.id,
            &device.id,
            owner_session_id,
            command.owner_security_version,
            lease_id,
            &assertion.pair_fingerprint,
            token_hash(&capability),
            &command.expires_at,
        ],
    )?;
    Ok(Some(capability))
}

impl Storage {
    pub fn complete_desktop_agent_disconnect(
        &self,
        command_id: &str,
        capability: &str,
        request: &DesktopAgentDisconnectCompletionRequest,
    ) -> ApiResult<()> {
        validate_disconnect_completion_request(&request.lease_id, request.event_sequence)?;
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let completion = completion_for_capability_in_tx(&tx, command_id, capability)?;
        ensure_completion_capability_live(&completion, now)?;
        let command = load_command_row_for_device_in_tx(&tx, command_id, &completion.device_id)?
            .ok_or(ApiError::NotFound)?;
        ensure_disconnect_completion_authorized_in_tx(&tx, &command, &completion)?;
        if request.lease_id != completion.lease_id {
            return Err(ApiError::Conflict);
        }
        if completion.completed_at.is_some() && completion_retry_matches(&tx, &command, request) {
            tx.commit()?;
            return Ok(());
        }
        if command.status.is_terminal() {
            return Err(ApiError::DesktopAgentDisconnectAuthorizationLost);
        }
        ensure_disconnect_command(&command, &completion, &request.lease_id, now, true)?;
        if completion.retirement_authorized_at.is_none() {
            return Err(ApiError::Conflict);
        }
        if command
            .lease_event_sequence
            .and_then(|sequence| sequence.checked_add(1))
            != Some(request.event_sequence)
        {
            return Err(ApiError::Conflict);
        }
        if command.status == DesktopAgentCommandStatus::CancelRequested {
            if !request.cancelled {
                return Err(ApiError::DesktopAgentCancellationRequested);
            }
            finish_disconnect_in_tx(
                &tx,
                command_id,
                &completion,
                DisconnectTerminal {
                    event_sequence: request.event_sequence,
                    at: &now_text,
                    status: DesktopAgentCommandStatus::Interrupted,
                    terminal_code: DesktopAgentTerminalCode::CancellationRequested,
                    result: None,
                },
            )?;
            tx.commit()?;
            return Ok(());
        }
        if request.cancelled {
            return Err(ApiError::Conflict);
        }
        let device_state = tx
            .query_row(
                "SELECT state FROM desktop_agent_devices WHERE id = ?1",
                [&completion.device_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(ApiError::Unauthenticated)?;
        if device_state != "frozen" {
            return Err(ApiError::DesktopAgentDisconnectAuthorizationLost);
        }
        finish_disconnect_in_tx(
            &tx,
            command_id,
            &completion,
            DisconnectTerminal {
                event_sequence: request.event_sequence,
                at: &now_text,
                status: DesktopAgentCommandStatus::Succeeded,
                terminal_code: DesktopAgentTerminalCode::Completed,
                result: Some(DesktopAgentResultPayload::Disconnect {
                    cleanup_completed: true,
                }),
            },
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn completion_for_capability_in_tx(
    tx: &Transaction<'_>,
    command_id: &str,
    capability: &str,
) -> ApiResult<CompletionRecord> {
    if !capability.starts_with(DISCONNECT_COMPLETION_SECRET_PREFIX) {
        return Err(ApiError::Unauthenticated);
    }
    tx.query_row(
        "SELECT device_id, owner_session_id, owner_security_version, lease_id, pair_fingerprint,
                retirement_assertion_hash, expires_at, retirement_authorized_at, completed_at
         FROM desktop_agent_disconnect_completions
         WHERE command_id = ?1 AND capability_hash = ?2",
        params![command_id, token_hash(capability)],
        |row| {
            Ok(CompletionRecord {
                device_id: row.get(0)?,
                owner_session_id: row.get(1)?,
                owner_security_version: row.get(2)?,
                lease_id: row.get(3)?,
                pair_fingerprint: row.get(4)?,
                retirement_assertion_hash: row.get(5)?,
                expires_at: row.get(6)?,
                retirement_authorized_at: row.get(7)?,
                completed_at: row.get(8)?,
            })
        },
    )
    .optional()?
    .ok_or(ApiError::Unauthenticated)
}

pub(super) fn ensure_disconnect_command(
    command: &CommandRow,
    completion: &CompletionRecord,
    lease_id: &str,
    now: DateTime<Utc>,
    allow_cancel_requested: bool,
) -> ApiResult<()> {
    if command.kind != DesktopAgentCommandKind::Disconnect
        || command.lease_id.as_deref() != Some(lease_id)
        || completion.lease_id != lease_id
        || !(matches!(
            command.status,
            DesktopAgentCommandStatus::Acknowledged | DesktopAgentCommandStatus::Running
        ) || allow_cancel_requested
            && command.status == DesktopAgentCommandStatus::CancelRequested)
        || !not_expired(&command.expires_at, now)
        || !not_expired(&completion.expires_at, now)
    {
        return Err(ApiError::Conflict);
    }
    Ok(())
}

pub(super) fn ensure_retirement_still_pending_in_tx(
    tx: &Transaction<'_>,
    command: &CommandRow,
    completion: &CompletionRecord,
) -> ApiResult<()> {
    ensure_disconnect_completion_authorized_in_tx(tx, command, completion)?;
    let state = tx
        .query_row(
            "SELECT state FROM desktop_agent_devices WHERE id = ?1",
            [&completion.device_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if state.as_deref() == Some("frozen") {
        Ok(())
    } else {
        Err(ApiError::DesktopAgentDisconnectAuthorizationLost)
    }
}

pub(super) fn ensure_disconnect_completion_authorized_in_tx(
    tx: &Transaction<'_>,
    command: &CommandRow,
    completion: &CompletionRecord,
) -> ApiResult<()> {
    let (email, is_admin, security_version) = tx
        .query_row(
            "SELECT email, is_admin, security_version FROM auth_accounts
             WHERE user_id = ?1 AND disabled_at IS NULL",
            [&command.owner_account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(ApiError::DesktopAgentDisconnectAuthorizationLost)?;
    if security_version != command.owner_security_version
        || security_version != completion.owner_security_version
        || (command.owner_is_admin_at_enqueue && is_admin == 0)
    {
        return Err(ApiError::DesktopAgentDisconnectAuthorizationLost);
    }
    if command.requester_kind == "user_session"
        && command.requester_id == completion.owner_session_id
    {
        let revoked_at = tx
            .query_row(
                "SELECT revoked_at FROM auth_sessions WHERE id = ?1 AND actor_email = ?2",
                params![&completion.owner_session_id, &email],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        if revoked_at == completion.retirement_authorized_at {
            return Ok(());
        }
        return Err(ApiError::DesktopAgentDisconnectAuthorizationLost);
    }
    ensure_command_source_active_in_tx(tx, command).map_err(disconnect_authorization_error)
}

fn completion_retry_matches(
    tx: &Transaction<'_>,
    command: &CommandRow,
    request: &DesktopAgentDisconnectCompletionRequest,
) -> bool {
    let (status, code, result_code, result) = if request.cancelled {
        (
            DesktopAgentCommandStatus::Interrupted,
            DesktopAgentTerminalCode::CancellationRequested,
            None,
            None,
        )
    } else {
        (
            DesktopAgentCommandStatus::Succeeded,
            DesktopAgentTerminalCode::Completed,
            Some(DesktopAgentResultCode::DisconnectCompleted),
            Some(DesktopAgentResultPayload::Disconnect {
                cleanup_completed: true,
            }),
        )
    };
    command.status == status
        && command.terminal_code == Some(code)
        && command.result_code == result_code
        && command.result == result
        && tx
            .query_row(
                "SELECT terminal_event_sequence FROM desktop_agent_commands WHERE id = ?1",
                [&command.id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .ok()
            .flatten()
            == Some(request.event_sequence)
}

pub(super) fn ensure_completion_capability_live(
    completion: &CompletionRecord,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    not_expired(&completion.expires_at, now)
        .then_some(())
        .ok_or(ApiError::DesktopAgentDisconnectCapabilityExpired)
}

fn disconnect_authorization_error(error: ApiError) -> ApiError {
    match error {
        ApiError::Unauthenticated | ApiError::Forbidden | ApiError::Conflict => {
            ApiError::DesktopAgentDisconnectAuthorizationLost
        }
        other => other,
    }
}

fn finish_disconnect_in_tx(
    tx: &Transaction<'_>,
    command_id: &str,
    completion: &CompletionRecord,
    terminal: DisconnectTerminal<'_>,
) -> ApiResult<()> {
    let result_code = (terminal.status == DesktopAgentCommandStatus::Succeeded)
        .then_some(DesktopAgentResultCode::DisconnectCompleted);
    terminalize_command_in_tx(
        tx,
        command_id,
        terminal.at,
        CommandEvent::terminal(
            terminal.status,
            terminal.terminal_code,
            result_code,
            terminal.result,
        ),
    )?;
    tx.execute(
        "UPDATE desktop_agent_commands SET terminal_event_sequence = ?1 WHERE id = ?2",
        params![terminal.event_sequence, command_id],
    )?;
    tx.execute(
        "UPDATE desktop_agent_disconnect_completions SET completed_at = ?1 WHERE command_id = ?2",
        params![terminal.at, command_id],
    )?;
    tx.execute(
        "UPDATE desktop_agent_devices
         SET state = 'retired', retired_at = COALESCE(retired_at, ?1), credential_hash = 'retired:' || id
         WHERE id = ?2 AND state = 'frozen'",
        params![terminal.at, &completion.device_id],
    )?;
    Ok(())
}

pub(super) fn not_expired(value: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .is_some_and(|expires_at| expires_at.with_timezone(&Utc) > now)
}

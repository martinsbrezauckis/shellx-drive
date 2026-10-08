use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    auth::{token_hash, Actor, AuthMode, DriveCredential},
    desktop_agent::{
        DesktopAgentCommandStatus, DesktopAgentDeviceAssertion, DesktopAgentDeviceState,
        DesktopAgentPhase, DesktopAgentResultCode, DesktopAgentResultPayload,
        DesktopAgentTerminalCode,
    },
    error::{ApiError, ApiResult},
};

use super::{
    authorization,
    rows::{max_event_sequence_in_tx, CommandRow, RequesterBinding},
    MAX_ACTIVE_COMMANDS_PER_DEVICE, MAX_ACTIVE_COMMANDS_PER_OWNER, MAX_COMMAND_EVENTS,
    MAX_STALE_LEASE_RECOVERY, MAX_TERMINAL_COMMANDS_PER_OWNER,
};

pub(super) struct DeviceGuard {
    pub id: String,
    pub state: DesktopAgentDeviceState,
    pub candidate_recovery: bool,
}

#[derive(Clone)]
pub(super) struct CommandEvent {
    pub status: DesktopAgentCommandStatus,
    pub phase: Option<DesktopAgentPhase>,
    pub progress_basis_points: Option<u16>,
    pub terminal_code: Option<DesktopAgentTerminalCode>,
    pub result_code: Option<DesktopAgentResultCode>,
    pub result: Option<DesktopAgentResultPayload>,
}

impl CommandEvent {
    pub const fn state(status: DesktopAgentCommandStatus) -> Self {
        Self {
            status,
            phase: None,
            progress_basis_points: None,
            terminal_code: None,
            result_code: None,
            result: None,
        }
    }

    pub const fn phase(
        status: DesktopAgentCommandStatus,
        phase: DesktopAgentPhase,
        progress_basis_points: Option<u16>,
    ) -> Self {
        Self {
            status,
            phase: Some(phase),
            progress_basis_points,
            terminal_code: None,
            result_code: None,
            result: None,
        }
    }

    pub const fn terminal(
        status: DesktopAgentCommandStatus,
        terminal_code: DesktopAgentTerminalCode,
        result_code: Option<DesktopAgentResultCode>,
        result: Option<DesktopAgentResultPayload>,
    ) -> Self {
        Self {
            status,
            phase: None,
            progress_basis_points: None,
            terminal_code: Some(terminal_code),
            result_code,
            result,
        }
    }

    pub const fn initial(
        status: DesktopAgentCommandStatus,
        terminal_code: Option<DesktopAgentTerminalCode>,
    ) -> Self {
        Self {
            status,
            phase: None,
            progress_basis_points: None,
            terminal_code,
            result_code: None,
            result: None,
        }
    }
}

pub(super) fn enum_db<T: Serialize>(value: T) -> ApiResult<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(|| ApiError::Validation("invalid_desktop_agent_state".to_string()))
}

pub(super) fn enum_from_db<T: DeserializeOwned>(value: &str) -> ApiResult<T> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|_| ApiError::Validation("invalid_desktop_agent_state".to_string()))
}

pub(super) fn account_binding_in_tx(
    tx: &Transaction<'_>,
    actor: &Actor,
) -> ApiResult<(String, i64)> {
    tx.query_row(
        "SELECT user_id, security_version FROM auth_accounts
         WHERE email = ?1 AND disabled_at IS NULL",
        [&actor.email],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()?
    .ok_or(ApiError::Unauthenticated)
}

pub(super) fn active_submission_owner_in_tx(
    tx: &Transaction<'_>,
    owner: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<(String, bool)> {
    if !matches!(
        source_credential,
        DriveCredential::UserSession(_) | DriveCredential::DelegatedAgentToken(_)
    ) {
        return Err(ApiError::Forbidden);
    }
    authorization::ensure_source_credential_active(tx, owner, source_credential)?;
    let (owner_account_id, _) = account_binding_in_tx(tx, owner)?;
    let owner_is_admin = tx.query_row(
        "SELECT is_admin FROM auth_accounts WHERE user_id = ?1 AND disabled_at IS NULL",
        [&owner_account_id],
        |row| row.get::<_, i64>(0),
    )? != 0;
    Ok((owner_account_id, owner_is_admin))
}

pub(super) fn requester_binding_in_tx(
    tx: &Transaction<'_>,
    owner_account_id: &str,
    source_credential: &DriveCredential,
) -> ApiResult<RequesterBinding> {
    let owner_security_version = tx.query_row(
        "SELECT security_version FROM auth_accounts WHERE user_id = ?1 AND disabled_at IS NULL",
        [owner_account_id],
        |row| row.get(0),
    )?;
    match source_credential {
        DriveCredential::UserSession(session_id) => Ok(RequesterBinding {
            kind: "user_session",
            credential_id: session_id.clone(),
            principal_id: format!("account:{owner_account_id}"),
            owner_security_version,
        }),
        DriveCredential::DelegatedAgentToken(token_id) => {
            let principal_id = tx
                .query_row(
                    "SELECT p.id FROM agent_tokens t
                     JOIN agent_principals p ON p.id = t.principal_id
                     WHERE t.id = ?1 AND p.created_by = (
                         SELECT email FROM auth_accounts WHERE user_id = ?2
                     )",
                    params![token_id, owner_account_id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(ApiError::Unauthenticated)?;
            Ok(RequesterBinding {
                kind: "delegated_agent",
                credential_id: token_id.clone(),
                principal_id,
                owner_security_version,
            })
        }
        DriveCredential::Operator | DriveCredential::AppToken(_) => Err(ApiError::Forbidden),
    }
}

pub(super) fn device_state_for_owner_in_tx(
    tx: &Transaction<'_>,
    device_id: &str,
    owner_account_id: &str,
) -> ApiResult<Option<DesktopAgentDeviceState>> {
    let state = tx
        .query_row(
            "SELECT state FROM desktop_agent_devices
             WHERE id = ?1 AND owner_account_id = ?2",
            params![device_id, owner_account_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    state.map(|state| enum_from_db(&state)).transpose()
}

pub(super) fn ensure_device_live_for_owner_in_tx(
    tx: &Transaction<'_>,
    device_id: &str,
    owner_account_id: &str,
) -> ApiResult<DeviceGuard> {
    let row = tx
        .query_row(
            "SELECT d.id, d.owner_session_id, d.owner_security_version, d.state,
                    d.candidate_recovery, a.email, a.is_admin, a.security_version
             FROM desktop_agent_devices d
             JOIN auth_accounts a ON a.user_id = d.owner_account_id
             WHERE d.id = ?1 AND d.owner_account_id = ?2 AND a.disabled_at IS NULL",
            params![device_id, owner_account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?
        .ok_or(ApiError::Unauthenticated)?;
    let (
        id,
        session_id,
        bound_security_version,
        state,
        candidate_recovery,
        email,
        is_admin,
        security_version,
    ) = row;
    if security_version != bound_security_version {
        return Err(ApiError::Unauthenticated);
    }
    let actor = Actor {
        email,
        is_admin: is_admin != 0,
        auth_mode: AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    };
    authorization::ensure_source_credential_active(
        tx,
        &actor,
        &DriveCredential::UserSession(session_id),
    )?;
    Ok(DeviceGuard {
        id,
        state: enum_from_db(&state)?,
        candidate_recovery: candidate_recovery != 0,
    })
}

pub(super) fn authenticate_device_in_tx(
    tx: &Transaction<'_>,
    device_id: &str,
    device_credential: &str,
    assertion: &DesktopAgentDeviceAssertion,
) -> ApiResult<DeviceGuard> {
    if !device_credential.starts_with(super::DEVICE_SECRET_PREFIX) {
        return Err(ApiError::Unauthenticated);
    }
    let credential_hash = token_hash(device_credential);
    let owner_account_id = tx
        .query_row(
            "SELECT owner_account_id FROM desktop_agent_devices
             WHERE id = ?1 AND credential_hash = ?2 AND state IN ('active', 'frozen')",
            params![device_id, credential_hash],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(ApiError::Unauthenticated)?;
    let guard = ensure_device_live_for_owner_in_tx(tx, device_id, &owner_account_id)?;
    let fingerprint = tx.query_row(
        "SELECT pair_fingerprint FROM desktop_agent_devices WHERE id = ?1",
        [&guard.id],
        |row| row.get::<_, String>(0),
    )?;
    if fingerprint != assertion.pair_fingerprint {
        return Err(ApiError::Unauthenticated);
    }
    tx.execute(
        "UPDATE desktop_agent_devices
         SET last_seen_at = ?1, app_version = ?2, candidate_recovery = ?3
         WHERE id = ?4 AND state IN ('active', 'frozen')",
        params![
            Utc::now().to_rfc3339(),
            &assertion.app_version,
            i64::from(assertion.candidate_recovery),
            &guard.id
        ],
    )?;
    Ok(guard)
}

pub(super) fn device_id_for_credential_in_tx(
    tx: &Transaction<'_>,
    device_credential: &str,
) -> ApiResult<String> {
    if !device_credential.starts_with(super::DEVICE_SECRET_PREFIX) {
        return Err(ApiError::Unauthenticated);
    }
    tx.query_row(
        "SELECT id FROM desktop_agent_devices
         WHERE credential_hash = ?1 AND state IN ('active', 'frozen')",
        [token_hash(device_credential)],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(ApiError::Unauthenticated)
}

pub(super) fn ensure_command_source_active_in_tx(
    tx: &Transaction<'_>,
    command: &CommandRow,
) -> ApiResult<()> {
    let owner = tx
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
        .ok_or(ApiError::Unauthenticated)?;
    let (email, is_admin, security_version) = owner;
    if security_version != command.owner_security_version {
        return Err(ApiError::Unauthenticated);
    }
    let current_is_admin = is_admin != 0;
    if command.owner_is_admin_at_enqueue && !current_is_admin {
        return Err(ApiError::Forbidden);
    }
    let (credential, auth_mode) = match command.requester_kind.as_str() {
        "user_session" => (
            DriveCredential::UserSession(command.requester_id.clone()),
            AuthMode::LocalAccount,
        ),
        "delegated_agent" => {
            let principal_matches = tx
                .query_row(
                    "SELECT 1 FROM agent_tokens t
                     JOIN agent_principals p ON p.id = t.principal_id
                     WHERE t.id = ?1 AND p.id = ?2 AND p.created_by = ?3",
                    params![
                        &command.requester_id,
                        &command.requester_principal_id,
                        &email
                    ],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !principal_matches {
                return Err(ApiError::Unauthenticated);
            }
            (
                DriveCredential::DelegatedAgentToken(command.requester_id.clone()),
                AuthMode::DelegatedAgent,
            )
        }
        _ => return Err(ApiError::Unauthenticated),
    };
    authorization::ensure_source_credential_active(
        tx,
        &Actor {
            email,
            is_admin: current_is_admin,
            auth_mode,
            allowed_workspace_ids: None,
        },
        &credential,
    )
}

pub(super) fn admit_command_capacity_in_tx(
    tx: &Transaction<'_>,
    owner_account_id: &str,
    device_id: Option<&str>,
) -> ApiResult<()> {
    let owner_active = active_command_count_in_tx(tx, "owner_account_id = ?1", owner_account_id)?;
    if owner_active >= MAX_ACTIVE_COMMANDS_PER_OWNER {
        return Err(ApiError::TooManyRequests);
    }
    if let Some(device_id) = device_id {
        let device_active = active_command_count_in_tx(tx, "device_id = ?1", device_id)?;
        if device_active >= MAX_ACTIVE_COMMANDS_PER_DEVICE {
            return Err(ApiError::TooManyRequests);
        }
    }
    Ok(())
}

pub(super) fn admit_terminal_command_capacity_in_tx(
    tx: &Transaction<'_>,
    owner_account_id: &str,
    now: &str,
) -> ApiResult<()> {
    tx.execute(
        "DELETE FROM desktop_agent_commands
         WHERE owner_account_id = ?1
           AND status IN ('succeeded', 'failed', 'rejected', 'cancelled', 'expired',
                          'interrupted', 'requires_local_gesture')
           AND julianday(expires_at) <= julianday(?2)",
        params![owner_account_id, now],
    )?;
    let retained = tx.query_row(
        "SELECT COUNT(*) FROM desktop_agent_commands
         WHERE owner_account_id = ?1
           AND status IN ('succeeded', 'failed', 'rejected', 'cancelled', 'expired',
                          'interrupted', 'requires_local_gesture')",
        [owner_account_id],
        |row| row.get::<_, i64>(0),
    )?;
    if retained >= MAX_TERMINAL_COMMANDS_PER_OWNER {
        return Err(ApiError::TooManyRequests);
    }
    Ok(())
}

pub(super) fn expire_queued_commands_for_owner_in_tx(
    tx: &Transaction<'_>,
    owner_account_id: &str,
    now: &str,
) -> ApiResult<()> {
    let mut statement = tx.prepare(
        "SELECT id FROM desktop_agent_commands WHERE owner_account_id = ?1 AND status = 'queued'
         AND julianday(expires_at) <= julianday(?2) ORDER BY expires_at ASC LIMIT 64",
    )?;
    let ids = statement
        .query_map(params![owner_account_id, now], |row| {
            row.get::<_, String>(0)
        })?
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

pub(super) fn insert_event_in_tx(
    tx: &Transaction<'_>,
    command_id: &str,
    sequence: i64,
    at: &str,
    event: CommandEvent,
) -> ApiResult<()> {
    if sequence <= 0 {
        return Err(ApiError::Validation(
            "invalid_desktop_agent_state".to_string(),
        ));
    }
    // Keep the durable event journal bounded without letting an old full
    // journal block revocation, freeze, expiry, or a truthful terminal state.
    tx.execute(
        "DELETE FROM desktop_agent_command_events
         WHERE command_id = ?1 AND sequence IN (
             SELECT sequence FROM desktop_agent_command_events
             WHERE command_id = ?1 ORDER BY sequence ASC
             LIMIT -1 OFFSET ?2
         )",
        params![command_id, MAX_COMMAND_EVENTS - 1],
    )?;
    tx.execute(
        "INSERT INTO desktop_agent_command_events (
             command_id, sequence, at, status, phase, progress_basis_points,
             terminal_code, result_code, result_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            command_id,
            sequence,
            at,
            enum_db(event.status)?,
            event.phase.map(enum_db).transpose()?,
            event.progress_basis_points.map(i64::from),
            event.terminal_code.map(enum_db).transpose()?,
            event.result_code.map(enum_db).transpose()?,
            event
                .result
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| ApiError::Validation("invalid_desktop_agent_state".to_string()))?,
        ],
    )?;
    Ok(())
}

pub(super) fn append_event_in_tx(
    tx: &Transaction<'_>,
    command_id: &str,
    at: &str,
    event: CommandEvent,
) -> ApiResult<()> {
    let next = max_event_sequence_in_tx(tx, command_id)? + 1;
    insert_event_in_tx(tx, command_id, next, at, event)
}

pub(super) fn invalidate_device_commands_in_tx(
    tx: &Transaction<'_>,
    device_id: &str,
    at: &str,
    terminal_code: DesktopAgentTerminalCode,
) -> ApiResult<()> {
    let mut statement = tx.prepare(
        "SELECT id, status FROM desktop_agent_commands
         WHERE device_id = ?1 AND status IN (
             'queued', 'leased', 'acknowledged', 'running', 'relaunch_pending', 'cancel_requested'
         ) ORDER BY created_at ASC LIMIT 32",
    )?;
    let rows = statement.query_map([device_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let commands = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (command_id, raw_status) in commands {
        let prior: DesktopAgentCommandStatus = enum_from_db(&raw_status)?;
        let status = if terminal_code == DesktopAgentTerminalCode::PendingDisconnect {
            if prior == DesktopAgentCommandStatus::Queued
                || prior == DesktopAgentCommandStatus::Leased
            {
                DesktopAgentCommandStatus::Rejected
            } else {
                DesktopAgentCommandStatus::Interrupted
            }
        } else if prior == DesktopAgentCommandStatus::Queued {
            DesktopAgentCommandStatus::Cancelled
        } else {
            DesktopAgentCommandStatus::Interrupted
        };
        tx.execute(
            "UPDATE desktop_agent_commands
             SET status = ?1, finished_at = ?2, terminal_code = ?3, result_code = NULL,
                 result_json = NULL,
                 lease_id = NULL, lease_expires_at = NULL, lease_event_sequence = NULL,
                 lease_phase = NULL, lease_progress_basis_points = NULL
             WHERE id = ?4",
            params![enum_db(status)?, at, enum_db(terminal_code)?, &command_id],
        )?;
        append_event_in_tx(
            tx,
            &command_id,
            at,
            CommandEvent::terminal(status, terminal_code, None, None),
        )?;
    }
    Ok(())
}

pub(super) fn recover_stale_leases_in_tx(
    tx: &Transaction<'_>,
    device_id: &str,
    at: &str,
) -> ApiResult<()> {
    let mut statement = tx.prepare(
        "SELECT id FROM desktop_agent_commands
         WHERE device_id = ?1 AND status IN (
             'leased', 'acknowledged', 'running', 'relaunch_pending', 'cancel_requested'
         )
           AND lease_expires_at IS NOT NULL AND julianday(lease_expires_at) <= julianday(?2)
         ORDER BY lease_expires_at ASC LIMIT ?3",
    )?;
    let ids = statement
        .query_map(params![device_id, at, MAX_STALE_LEASE_RECOVERY], |row| {
            row.get(0)
        })?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    drop(statement);
    for command_id in ids {
        let Some(command) =
            super::rows::load_command_row_for_device_in_tx(tx, &command_id, device_id)?
        else {
            continue;
        };
        let active = ensure_command_source_active_in_tx(tx, &command).is_ok();
        let status = if active
            && command.status == DesktopAgentCommandStatus::Leased
            && command.kind.lease_replay_safe()
        {
            DesktopAgentCommandStatus::Queued
        } else {
            DesktopAgentCommandStatus::Interrupted
        };
        let code = if active {
            DesktopAgentTerminalCode::LeaseExpired
        } else {
            DesktopAgentTerminalCode::AuthorizationLost
        };
        tx.execute(
            "UPDATE desktop_agent_commands
             SET status = ?1, finished_at = CASE WHEN ?1 = 'queued' THEN NULL ELSE ?2 END,
                 terminal_code = CASE WHEN ?1 = 'queued' THEN NULL ELSE ?3 END,
                 result_code = NULL, result_json = NULL, lease_id = NULL, lease_expires_at = NULL,
                 lease_event_sequence = NULL, lease_phase = NULL,
                 lease_progress_basis_points = NULL
             WHERE id = ?4",
            params![enum_db(status)?, at, enum_db(code)?, &command_id],
        )?;
        append_event_in_tx(
            tx,
            &command_id,
            at,
            if status == DesktopAgentCommandStatus::Queued {
                CommandEvent::state(status)
            } else {
                CommandEvent::terminal(status, code, None, None)
            },
        )?;
    }
    Ok(())
}

pub(super) fn recover_stale_leases_for_owner_in_tx(
    tx: &Transaction<'_>,
    owner_account_id: &str,
    at: &str,
) -> ApiResult<()> {
    let mut statement = tx.prepare(
        "SELECT DISTINCT device_id FROM desktop_agent_commands
         WHERE owner_account_id = ?1 AND device_id IS NOT NULL
           AND status IN ('leased', 'acknowledged', 'running', 'relaunch_pending', 'cancel_requested')
           AND lease_expires_at IS NOT NULL AND julianday(lease_expires_at) <= julianday(?2)
         ORDER BY device_id ASC LIMIT 16",
    )?;
    let device_ids = statement
        .query_map(params![owner_account_id, at], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for device_id in device_ids {
        recover_stale_leases_in_tx(tx, &device_id, at)?;
    }
    Ok(())
}

pub(super) fn device_has_active_command_in_tx(
    tx: &Transaction<'_>,
    device_id: &str,
) -> ApiResult<bool> {
    Ok(tx.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM desktop_agent_commands
             WHERE device_id = ?1 AND status IN (
                 'leased', 'acknowledged', 'running', 'relaunch_pending', 'cancel_requested'
             )
         )",
        [device_id],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

pub(super) fn terminalize_command_in_tx(
    tx: &Transaction<'_>,
    command_id: &str,
    at: &str,
    event: CommandEvent,
) -> ApiResult<()> {
    let terminal_code = event
        .terminal_code
        .ok_or_else(|| ApiError::Validation("invalid_desktop_agent_state".to_string()))?;
    let result_json = event
        .result
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| ApiError::Validation("invalid_desktop_agent_state".to_string()))?;
    tx.execute(
        "UPDATE desktop_agent_commands
         SET status = ?1, finished_at = ?2, terminal_code = ?3, result_code = ?4, result_json = ?5,
             lease_id = NULL, lease_expires_at = NULL, lease_event_sequence = NULL,
             lease_phase = NULL, lease_progress_basis_points = NULL
         WHERE id = ?6",
        params![
            enum_db(event.status)?,
            at,
            enum_db(terminal_code)?,
            event.result_code.map(enum_db).transpose()?,
            result_json,
            command_id,
        ],
    )?;
    append_event_in_tx(tx, command_id, at, event)
}

fn active_command_count_in_tx(tx: &Transaction<'_>, scope: &str, value: &str) -> ApiResult<i64> {
    let sql = format!(
        "SELECT COUNT(*) FROM desktop_agent_commands WHERE {scope}
         AND status IN ('queued', 'leased', 'acknowledged', 'running', 'relaunch_pending', 'cancel_requested')"
    );
    Ok(tx.query_row(&sql, [value], |row| row.get(0))?)
}

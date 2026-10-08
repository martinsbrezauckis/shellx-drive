use rusqlite::{params, OptionalExtension, Row, Transaction};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    desktop_agent::{
        DesktopAgentCommand, DesktopAgentCommandEvent, DesktopAgentCommandKind,
        DesktopAgentCommandPayload, DesktopAgentCommandStatus, DesktopAgentDevice,
        DesktopAgentResultCode, DesktopAgentResultPayload, DesktopAgentTerminalCode,
    },
    error::{ApiError, ApiResult},
};

use super::enum_from_db;

#[derive(Debug, Clone)]
pub(super) struct RequesterBinding {
    pub kind: &'static str,
    pub credential_id: String,
    pub principal_id: String,
    pub owner_security_version: i64,
}

#[derive(Debug, Clone)]
pub(super) struct IdempotentCommand {
    pub id: String,
    pub kind: DesktopAgentCommandKind,
    pub payload_hash: String,
}

#[derive(Debug, Clone)]
pub(super) struct CommandRow {
    pub id: String,
    pub owner_account_id: String,
    pub device_id: Option<String>,
    pub requester_kind: String,
    pub requester_id: String,
    pub requester_principal_id: String,
    pub owner_is_admin_at_enqueue: bool,
    pub owner_security_version: i64,
    pub kind: DesktopAgentCommandKind,
    pub payload: DesktopAgentCommandPayload,
    pub expires_at: String,
    pub status: DesktopAgentCommandStatus,
    pub lease_id: Option<String>,
    pub lease_expires_at: Option<String>,
    pub lease_event_sequence: Option<i64>,
    pub created_at: String,
    pub terminal_code: Option<DesktopAgentTerminalCode>,
    pub result_code: Option<DesktopAgentResultCode>,
    pub result: Option<DesktopAgentResultPayload>,
}

pub(super) fn row_to_device(row: &Row<'_>) -> rusqlite::Result<DesktopAgentDevice> {
    Ok(DesktopAgentDevice {
        id: row.get(0)?,
        platform: row_enum(row.get::<_, String>(1)?)?,
        app_version: row.get(2)?,
        state: row_enum(row.get::<_, String>(3)?)?,
        last_seen_at: row.get(4)?,
        last_ready_at: row.get(5)?,
        created_at: row.get(6)?,
    })
}

pub(super) fn idempotent_command_in_tx(
    tx: &Transaction<'_>,
    owner_account_id: &str,
    requester_principal_id: &str,
    target_key: &str,
    request_id: &str,
) -> ApiResult<Option<IdempotentCommand>> {
    let row = tx
        .query_row(
            "SELECT id, kind, payload_hash
             FROM desktop_agent_commands
             WHERE owner_account_id = ?1 AND requester_principal_id = ?2
               AND target_key = ?3 AND request_id = ?4",
            params![
                owner_account_id,
                requester_principal_id,
                target_key,
                request_id
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(id, kind, payload_hash)| {
        Ok(IdempotentCommand {
            id,
            kind: enum_from_db(&kind)?,
            payload_hash,
        })
    })
    .transpose()
}

pub(super) fn load_command_for_owner_in_tx(
    tx: &Transaction<'_>,
    command_id: &str,
    owner_account_id: &str,
) -> ApiResult<Option<DesktopAgentCommand>> {
    load_command_row_in_tx(tx, command_id, Some(owner_account_id))?
        .map(|row| command_from_row(tx, row))
        .transpose()
}

pub(super) fn load_command_row_for_device_in_tx(
    tx: &Transaction<'_>,
    command_id: &str,
    device_id: &str,
) -> ApiResult<Option<CommandRow>> {
    load_command_row_by_clause(tx, command_id, "device_id = ?2", device_id)
}

pub(super) fn load_command_row_in_tx(
    tx: &Transaction<'_>,
    command_id: &str,
    owner_account_id: Option<&str>,
) -> ApiResult<Option<CommandRow>> {
    match owner_account_id {
        Some(owner_account_id) => {
            load_command_row_by_clause(tx, command_id, "owner_account_id = ?2", owner_account_id)
        }
        None => {
            let raw = tx
                .query_row(
                    "SELECT id, owner_account_id, device_id, requester_kind, requester_id,
                            requester_principal_id, owner_is_admin_at_enqueue,
                            owner_security_version, kind, payload_json, expires_at, status,
                            lease_id, lease_expires_at, lease_event_sequence, created_at,
                            terminal_code, result_code, result_json
                     FROM desktop_agent_commands WHERE id = ?1",
                    [command_id],
                    row_to_command_raw,
                )
                .optional()?;
            raw.map(command_row_from_raw).transpose()
        }
    }
}

fn load_command_row_by_clause(
    tx: &Transaction<'_>,
    command_id: &str,
    clause: &str,
    scope: &str,
) -> ApiResult<Option<CommandRow>> {
    let sql = format!(
        "SELECT id, owner_account_id, device_id, requester_kind, requester_id,
                requester_principal_id, owner_is_admin_at_enqueue, owner_security_version,
                kind, payload_json, expires_at, status, lease_id, lease_expires_at,
                lease_event_sequence, created_at, terminal_code, result_code, result_json
         FROM desktop_agent_commands WHERE id = ?1 AND {clause}"
    );
    let raw = tx
        .query_row(&sql, params![command_id, scope], row_to_command_raw)
        .optional()?;
    raw.map(command_row_from_raw).transpose()
}

pub(super) fn command_from_row(
    tx: &Transaction<'_>,
    row: CommandRow,
) -> ApiResult<DesktopAgentCommand> {
    let mut statement = tx.prepare(
        "SELECT sequence, at, status, phase, progress_basis_points, terminal_code, result_code,
                result_json
         FROM desktop_agent_command_events WHERE command_id = ?1
         ORDER BY sequence ASC LIMIT 64",
    )?;
    let event_rows = statement.query_map([&row.id], row_to_event_raw)?;
    let events = event_rows
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .map(event_from_raw)
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(DesktopAgentCommand {
        id: row.id,
        device_id: row.device_id,
        kind: row.kind,
        status: row.status,
        created_at: row.created_at,
        expires_at: row.expires_at,
        lease_expires_at: row.lease_expires_at,
        events,
        terminal_code: row.terminal_code,
        result_code: row.result_code,
        result: row.result,
    })
}

pub(super) fn max_event_sequence_in_tx(tx: &Transaction<'_>, command_id: &str) -> ApiResult<i64> {
    Ok(tx.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM desktop_agent_command_events WHERE command_id = ?1",
        [command_id],
        |row| row.get(0),
    )?)
}

pub(super) fn row_enum<T: DeserializeOwned>(raw: String) -> rusqlite::Result<T> {
    serde_json::from_value(Value::String(raw)).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn row_to_command_raw(row: &Row<'_>) -> rusqlite::Result<CommandRaw> {
    Ok(CommandRaw {
        id: row.get(0)?,
        owner_account_id: row.get(1)?,
        device_id: row.get(2)?,
        requester_kind: row.get(3)?,
        requester_id: row.get(4)?,
        requester_principal_id: row.get(5)?,
        owner_is_admin_at_enqueue: row.get::<_, i64>(6)? != 0,
        owner_security_version: row.get(7)?,
        kind: row.get(8)?,
        payload_json: row.get(9)?,
        expires_at: row.get(10)?,
        status: row.get(11)?,
        lease_id: row.get(12)?,
        lease_expires_at: row.get(13)?,
        lease_event_sequence: row.get(14)?,
        created_at: row.get(15)?,
        terminal_code: row.get(16)?,
        result_code: row.get(17)?,
        result_json: row.get(18)?,
    })
}

fn command_row_from_raw(raw: CommandRaw) -> ApiResult<CommandRow> {
    Ok(CommandRow {
        id: raw.id,
        owner_account_id: raw.owner_account_id,
        device_id: raw.device_id,
        requester_kind: raw.requester_kind,
        requester_id: raw.requester_id,
        requester_principal_id: raw.requester_principal_id,
        owner_is_admin_at_enqueue: raw.owner_is_admin_at_enqueue,
        owner_security_version: raw.owner_security_version,
        kind: enum_from_db(&raw.kind)?,
        payload: serde_json::from_str(&raw.payload_json)
            .map_err(|_| ApiError::Validation("invalid_desktop_agent_state".to_string()))?,
        expires_at: raw.expires_at,
        status: enum_from_db(&raw.status)?,
        lease_id: raw.lease_id,
        lease_expires_at: raw.lease_expires_at,
        lease_event_sequence: raw.lease_event_sequence,
        created_at: raw.created_at,
        terminal_code: raw
            .terminal_code
            .map(|raw| enum_from_db(&raw))
            .transpose()?,
        result_code: raw.result_code.map(|raw| enum_from_db(&raw)).transpose()?,
        result: raw
            .result_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| ApiError::Validation("invalid_desktop_agent_state".to_string()))?,
    })
}

fn row_to_event_raw(row: &Row<'_>) -> rusqlite::Result<EventRaw> {
    Ok(EventRaw {
        sequence: row.get(0)?,
        at: row.get(1)?,
        status: row.get(2)?,
        phase: row.get(3)?,
        progress_basis_points: row.get(4)?,
        terminal_code: row.get(5)?,
        result_code: row.get(6)?,
        result_json: row.get(7)?,
    })
}

fn event_from_raw(raw: EventRaw) -> ApiResult<DesktopAgentCommandEvent> {
    let progress_basis_points = raw
        .progress_basis_points
        .map(|value: i64| u16::try_from(value))
        .transpose()
        .map_err(|_| ApiError::Validation("invalid_desktop_agent_state".to_string()))?;
    Ok(DesktopAgentCommandEvent {
        sequence: raw.sequence,
        at: raw.at,
        status: enum_from_db(&raw.status)?,
        phase: raw.phase.map(|raw| enum_from_db(&raw)).transpose()?,
        progress_basis_points,
        terminal_code: raw
            .terminal_code
            .map(|raw| enum_from_db(&raw))
            .transpose()?,
        result_code: raw.result_code.map(|raw| enum_from_db(&raw)).transpose()?,
        result: raw
            .result_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| ApiError::Validation("invalid_desktop_agent_state".to_string()))?,
    })
}

struct CommandRaw {
    id: String,
    owner_account_id: String,
    device_id: Option<String>,
    requester_kind: String,
    requester_id: String,
    requester_principal_id: String,
    owner_is_admin_at_enqueue: bool,
    owner_security_version: i64,
    kind: String,
    payload_json: String,
    expires_at: String,
    status: String,
    lease_id: Option<String>,
    lease_expires_at: Option<String>,
    lease_event_sequence: Option<i64>,
    created_at: String,
    terminal_code: Option<String>,
    result_code: Option<String>,
    result_json: Option<String>,
}

struct EventRaw {
    sequence: i64,
    at: String,
    status: String,
    phase: Option<String>,
    progress_basis_points: Option<i64>,
    terminal_code: Option<String>,
    result_code: Option<String>,
    result_json: Option<String>,
}

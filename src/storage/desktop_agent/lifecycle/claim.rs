use rusqlite::{OptionalExtension, Transaction};

use crate::{
    desktop_agent::{DesktopAgentCommandStatus, DesktopAgentTerminalCode},
    error::ApiResult,
};

use super::super::{
    guards::{terminalize_command_in_tx, CommandEvent},
    rows::{load_command_row_for_device_in_tx, CommandRow},
};

pub(super) fn next_queued_command_in_tx(
    tx: &Transaction<'_>,
    device_id: &str,
) -> ApiResult<Option<CommandRow>> {
    let id = tx
        .query_row(
            "SELECT id FROM desktop_agent_commands
             WHERE device_id = ?1 AND status = 'queued' ORDER BY created_at ASC, id ASC LIMIT 1",
            [device_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    id.map(|id| load_command_row_for_device_in_tx(tx, &id, device_id))
        .transpose()
        .map(Option::flatten)
}

/// Old review rows have no exact pair binding. Retain them for owner history,
/// but reject them before a device can receive a mutation it cannot prove.
pub(super) fn reject_unclaimable_command_in_tx(
    tx: &Transaction<'_>,
    command: &CommandRow,
    now: &str,
) -> ApiResult<bool> {
    if command.payload.is_claimable() {
        return Ok(false);
    }
    terminalize_command_in_tx(
        tx,
        &command.id,
        now,
        CommandEvent::terminal(
            DesktopAgentCommandStatus::Rejected,
            DesktopAgentTerminalCode::ProtocolViolation,
            None,
            None,
        ),
    )?;
    Ok(true)
}

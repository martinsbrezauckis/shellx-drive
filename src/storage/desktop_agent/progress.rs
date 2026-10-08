//! Command-specific admission checks for durable progress events.

use rusqlite::Transaction;

use crate::{
    desktop_agent::{DesktopAgentCommandKind, DesktopAgentCommandStatus, DesktopAgentPhase},
    error::{ApiError, ApiResult},
};

use super::rows::CommandRow;

/// A restart grace is meaningful only after this exact update command has
/// reported verified update progress. Other commands cannot become pending
/// restart work through a generic progress phase.
pub(super) fn validate_progress_phase_for_command(
    tx: &Transaction<'_>,
    command: &CommandRow,
    phase: DesktopAgentPhase,
) -> ApiResult<()> {
    if phase != DesktopAgentPhase::RelaunchPending {
        return Ok(());
    }
    if command.kind != DesktopAgentCommandKind::InstallDesktopUpdate {
        return Err(invalid_progress());
    }
    let valid_predecessor = match command.status {
        DesktopAgentCommandStatus::Running => {
            tx.query_row(
                "SELECT lease_phase FROM desktop_agent_commands WHERE id = ?1",
                [&command.id],
                |row| row.get::<_, Option<String>>(0),
            )? == Some("updating".to_string())
        }
        DesktopAgentCommandStatus::RelaunchPending => true,
        _ => false,
    };
    valid_predecessor.then_some(()).ok_or_else(invalid_progress)
}

fn invalid_progress() -> ApiError {
    ApiError::Validation("invalid_desktop_agent_progress".to_string())
}

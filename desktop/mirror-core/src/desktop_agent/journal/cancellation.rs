//! Exact conversion of an unaccepted terminal after broker cancellation.

use chrono::{DateTime, Utc};

use crate::{DesktopError, Result};

use super::{
    DesktopAgentCommandJournalState, DesktopAgentControlState, DesktopAgentJournalRecovery,
    DesktopAgentTerminalCode, DesktopAgentTerminalStatus,
};

impl DesktopAgentControlState {
    /// Replace a progress request the broker rejected for cancellation with
    /// the terminal in that same event slot. The reserved sequence is not
    /// consumed by the rejected progress request.
    pub fn replace_pending_progress_with_cancellation(
        &mut self,
        command_id: &str,
        event_sequence: u64,
        now: DateTime<Utc>,
    ) -> Result<DesktopAgentJournalRecovery> {
        let entry = self
            .command_journal
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent command is not in the durable journal".to_string(),
                )
            })?;
        if entry.pending_progress_event_sequence != Some(event_sequence)
            || entry.pending_progress_phase.is_none()
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent cancellation does not match a pending progress event".to_string(),
            ));
        }
        entry.state = DesktopAgentCommandJournalState::TerminalReporting;
        entry.pending_terminal_status = Some(DesktopAgentTerminalStatus::Interrupted);
        entry.terminal_code = Some(DesktopAgentTerminalCode::CancellationRequested);
        entry.result_code = None;
        entry.result = None;
        entry.terminal_event_sequence = Some(event_sequence);
        entry.pending_progress_phase = None;
        entry.pending_progress_event_sequence = None;
        entry.updated_at = now;
        entry.abandonment_reason = None;
        let lease_id = entry.lease_id.clone();
        self.last_terminal_command_id = Some(command_id.to_string());
        Ok(DesktopAgentJournalRecovery {
            command_id: command_id.to_string(),
            lease_id,
            event_sequence,
            terminal_status: DesktopAgentTerminalStatus::Interrupted,
            terminal_code: DesktopAgentTerminalCode::CancellationRequested,
            result_code: None,
            result: None,
        })
    }

    /// Replace an unaccepted terminal with the broker's cancellation outcome
    /// without allocating a new event sequence. The server can therefore
    /// recognize the same terminal slot after it changed command disposition.
    pub fn replace_pending_terminal_with_cancellation(
        &mut self,
        command_id: &str,
        now: DateTime<Utc>,
    ) -> Result<DesktopAgentJournalRecovery> {
        let entry = self
            .command_journal
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent command is not in the durable journal".to_string(),
                )
            })?;
        if entry.state != DesktopAgentCommandJournalState::TerminalReporting {
            return Err(DesktopError::InvalidState(
                "desktop-agent cancellation can replace only a pending terminal".to_string(),
            ));
        }
        let event_sequence = entry.terminal_event_sequence.ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent cancellation has no pending terminal sequence".to_string(),
            )
        })?;
        entry.pending_terminal_status = Some(DesktopAgentTerminalStatus::Interrupted);
        entry.terminal_code = Some(DesktopAgentTerminalCode::CancellationRequested);
        entry.result_code = None;
        entry.result = None;
        entry.updated_at = now;
        entry.abandonment_reason = None;
        let lease_id = entry.lease_id.clone();
        self.last_terminal_command_id = Some(command_id.to_string());
        Ok(DesktopAgentJournalRecovery {
            command_id: command_id.to_string(),
            lease_id,
            event_sequence,
            terminal_status: DesktopAgentTerminalStatus::Interrupted,
            terminal_code: DesktopAgentTerminalCode::CancellationRequested,
            result_code: None,
            result: None,
        })
    }
}

//! Durable journal shape validation.

use crate::{DesktopError, Result};

use super::super::{
    ensure_fingerprint, ensure_opaque_id, DesktopAgentCommandJournalState,
    DesktopAgentControlState, DesktopAgentTerminalStatus, MAX_DESKTOP_AGENT_JOURNAL_ENTRIES,
};

impl DesktopAgentControlState {
    pub(crate) fn validate(&self) -> Result<()> {
        match (self.enabled, &self.device_id, &self.pair_fingerprint) {
            (true, Some(device_id), Some(fingerprint)) => {
                ensure_opaque_id("desktop-agent device ID", device_id)?;
                ensure_fingerprint(fingerprint)?;
            }
            (true, _, _) => {
                return Err(DesktopError::InvalidState(
                    "enabled desktop-agent control must have a device ID and pair fingerprint"
                        .to_string(),
                ));
            }
            (false, None, None) => {}
            (false, _, _) => {
                return Err(DesktopError::InvalidState(
                    "disabled desktop-agent control must not retain device enrollment state"
                        .to_string(),
                ));
            }
        }
        if let Some(command_id) = self.last_terminal_command_id.as_deref() {
            ensure_opaque_id("desktop-agent last terminal command ID", command_id)?;
        }
        if self.command_journal.len() > MAX_DESKTOP_AGENT_JOURNAL_ENTRIES {
            return Err(DesktopError::InvalidState(format!(
                "desktop-agent command journal exceeds {MAX_DESKTOP_AGENT_JOURNAL_ENTRIES} entries"
            )));
        }
        for entry in &self.command_journal {
            ensure_opaque_id("desktop-agent command ID", &entry.command_id)?;
            ensure_opaque_id("desktop-agent lease ID", &entry.lease_id)?;
            if entry.next_event_sequence == 0 {
                return Err(DesktopError::InvalidState(
                    "desktop-agent command journal has an invalid event sequence".to_string(),
                ));
            }
            let pending_progress_shape_valid = entry.pending_progress_phase.is_some()
                == entry.pending_progress_event_sequence.is_some();
            if !pending_progress_shape_valid {
                return Err(DesktopError::InvalidState(
                    "desktop-agent command journal progress retry fields disagree".to_string(),
                ));
            }
            let terminal_status = if entry.state.is_terminal()
                && entry.state != DesktopAgentCommandJournalState::Abandoned
            {
                Some(match entry.state {
                    DesktopAgentCommandJournalState::Succeeded => {
                        DesktopAgentTerminalStatus::Succeeded
                    }
                    DesktopAgentCommandJournalState::Failed => DesktopAgentTerminalStatus::Failed,
                    DesktopAgentCommandJournalState::Rejected => {
                        DesktopAgentTerminalStatus::Rejected
                    }
                    DesktopAgentCommandJournalState::Interrupted => {
                        DesktopAgentTerminalStatus::Interrupted
                    }
                    DesktopAgentCommandJournalState::Abandoned => {
                        unreachable!("abandoned records have no accepted terminal status")
                    }
                    _ => unreachable!("terminal journal state was checked"),
                })
            } else {
                entry.pending_terminal_status
            };
            let result_shape_valid = match terminal_status {
                Some(DesktopAgentTerminalStatus::Succeeded) => entry
                    .result_code
                    .zip(entry.result.as_ref())
                    .map(|(code, result)| result.validate_for(entry.kind, code).is_ok())
                    .unwrap_or(false),
                Some(_) => entry.result_code.is_none() && entry.result.is_none(),
                None => entry.result_code.is_none() && entry.result.is_none(),
            };
            let terminal_shape_valid = if entry.state == DesktopAgentCommandJournalState::Abandoned
            {
                entry.abandonment_reason.is_some()
                    && entry.terminal_code.is_none()
                    && entry.pending_terminal_status.is_none()
                    && entry.terminal_event_sequence.is_none()
                    && entry.pending_progress_event_sequence.is_none()
                    && result_shape_valid
            } else if entry.state.is_terminal() {
                entry.terminal_code.is_some()
                    && entry.pending_terminal_status.is_none()
                    && entry.terminal_event_sequence.is_some()
                    && entry.pending_progress_event_sequence.is_none()
                    && entry.abandonment_reason.is_none()
                    && result_shape_valid
            } else if entry.state == DesktopAgentCommandJournalState::TerminalReporting {
                entry.terminal_code.is_some()
                    && entry.pending_terminal_status.is_some()
                    && entry.terminal_event_sequence.is_some()
                    && entry.pending_progress_event_sequence.is_none()
                    && entry.abandonment_reason.is_none()
                    && result_shape_valid
            } else {
                entry.terminal_code.is_none()
                    && entry.pending_terminal_status.is_none()
                    && entry.terminal_event_sequence.is_none()
                    && entry.abandonment_reason.is_none()
                    && result_shape_valid
            };
            if !terminal_shape_valid {
                return Err(DesktopError::InvalidState(
                    "desktop-agent command journal terminal outcome fields disagree".to_string(),
                ));
            }
        }
        if self
            .command_journal
            .windows(2)
            .any(|entries| entries[0].updated_at > entries[1].updated_at)
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent command journal must be ordered by update time".to_string(),
            ));
        }
        if self
            .command_journal
            .iter()
            .enumerate()
            .any(|(index, entry)| {
                self.command_journal[..index]
                    .iter()
                    .any(|previous| previous.command_id == entry.command_id)
            })
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent command journal repeats a command ID".to_string(),
            ));
        }
        Ok(())
    }
}

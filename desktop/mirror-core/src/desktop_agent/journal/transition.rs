//! Compact values for atomic journal state transitions.

use chrono::{DateTime, Utc};

use super::super::{
    DesktopAgentCommandJournalState, DesktopAgentResultCode, DesktopAgentResultPayload,
    DesktopAgentTerminalCode, DesktopAgentTerminalStatus,
};

pub(super) struct JournalTransition {
    pub(super) state: DesktopAgentCommandJournalState,
    pub(super) now: DateTime<Utc>,
    pub(super) terminal: Option<JournalTerminal>,
}

pub(super) struct JournalTerminal {
    pub(super) status: DesktopAgentTerminalStatus,
    pub(super) code: DesktopAgentTerminalCode,
    pub(super) result_code: Option<DesktopAgentResultCode>,
    pub(super) result: Option<DesktopAgentResultPayload>,
}

impl JournalTransition {
    pub(super) fn acknowledgement(now: DateTime<Utc>) -> Self {
        Self {
            state: DesktopAgentCommandJournalState::Acknowledged,
            now,
            terminal: None,
        }
    }

    pub(super) fn terminal(now: DateTime<Utc>, terminal: JournalTerminal) -> Self {
        Self {
            state: DesktopAgentCommandJournalState::TerminalReporting,
            now,
            terminal: Some(terminal),
        }
    }
}

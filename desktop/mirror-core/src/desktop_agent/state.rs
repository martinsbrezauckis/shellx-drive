//! Durable non-secret journal and enrollment state for desktop-agent work.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{DesktopError, Result};

use super::{
    ensure_fingerprint, ensure_opaque_id, DesktopAgentCommandKind, DesktopAgentProgressPhase,
    DesktopAgentResultCode, DesktopAgentResultPayload, DesktopAgentTerminalCode,
    DesktopAgentTerminalStatus, MAX_DESKTOP_AGENT_JOURNAL_ENTRIES,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentCommandJournalState {
    Leased,
    Acknowledged,
    Running,
    RelaunchPending,
    TerminalReporting,
    Succeeded,
    Failed,
    Rejected,
    Interrupted,
    /// The broker authoritatively refused a pending retry. This is a local
    /// final disposition, never a broker-accepted terminal outcome.
    Abandoned,
}

impl DesktopAgentCommandJournalState {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Rejected | Self::Interrupted | Self::Abandoned
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentAbandonmentReason {
    AuthorizationLost,
    BrokerConflict,
    CommandUnavailable,
}

/// One bounded, non-secret durable command record. `lease_id` is an opaque
/// server locator, not a credential; it is necessary to truthfully report an
/// interruption after the desktop restarts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DesktopAgentCommandJournalEntry {
    pub command_id: String,
    pub lease_id: String,
    pub kind: DesktopAgentCommandKind,
    pub state: DesktopAgentCommandJournalState,
    pub next_event_sequence: u64,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub terminal_code: Option<DesktopAgentTerminalCode>,
    #[serde(default)]
    pub pending_terminal_status: Option<DesktopAgentTerminalStatus>,
    #[serde(default)]
    pub result_code: Option<DesktopAgentResultCode>,
    #[serde(default)]
    pub result: Option<DesktopAgentResultPayload>,
    /// Sequence of the persisted terminal request. It is retained after a
    /// response loss so the server can recognize an exact idempotent retry.
    #[serde(default)]
    pub terminal_event_sequence: Option<u64>,
    /// A progress request is retained until its 204 response arrives. This
    /// permits an exact idempotent retry after a response loss and prevents a
    /// later terminal event from skipping an unconfirmed sequence.
    #[serde(default)]
    pub pending_progress_phase: Option<DesktopAgentProgressPhase>,
    #[serde(default)]
    pub pending_progress_event_sequence: Option<u64>,
    #[serde(default)]
    pub abandonment_reason: Option<DesktopAgentAbandonmentReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopAgentJournalRecovery {
    pub command_id: String,
    pub lease_id: String,
    pub event_sequence: u64,
    pub terminal_status: DesktopAgentTerminalStatus,
    pub terminal_code: DesktopAgentTerminalCode,
    pub result_code: Option<DesktopAgentResultCode>,
    pub result: Option<DesktopAgentResultPayload>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopAgentPendingProgress {
    pub command_id: String,
    pub lease_id: String,
    pub event_sequence: u64,
    pub phase: DesktopAgentProgressPhase,
}

/// Non-secret opt-in state. Clearing enrollment is allowed only after the
/// server confirms retire/revoke; this type contains no local deletion path.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DesktopAgentControlState {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub credential_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    /// Historical field name retained for serialized compatibility. A new
    /// enrollment stores its server/account identity digest here.
    pub pair_fingerprint: Option<String>,
    /// The exact terminal request most recently committed locally. It is sent
    /// in every assertion so a lost terminal response can be retried verbatim.
    #[serde(default)]
    pub last_terminal_command_id: Option<String>,
    #[serde(default)]
    pub command_journal: Vec<DesktopAgentCommandJournalEntry>,
}

impl DesktopAgentControlState {
    pub fn enroll(
        &mut self,
        device_id: String,
        credential_expires_at: Option<DateTime<Utc>>,
        pair_fingerprint: String,
    ) -> Result<()> {
        ensure_opaque_id("desktop-agent device ID", &device_id)?;
        ensure_fingerprint(&pair_fingerprint)?;
        self.enabled = true;
        self.device_id = Some(device_id);
        self.credential_expires_at = credential_expires_at;
        self.pair_fingerprint = Some(pair_fingerprint);
        self.last_terminal_command_id = None;
        self.command_journal.clear();
        Ok(())
    }

    pub fn clear_after_retirement(&mut self) {
        self.enabled = false;
        self.device_id = None;
        self.credential_expires_at = None;
        self.pair_fingerprint = None;
        self.last_terminal_command_id = None;
        self.command_journal.clear();
    }

    pub fn record_lease(
        &mut self,
        command_id: String,
        lease_id: String,
        kind: DesktopAgentCommandKind,
        now: DateTime<Utc>,
    ) -> Result<()> {
        ensure_opaque_id("desktop-agent command ID", &command_id)?;
        ensure_opaque_id("desktop-agent lease ID", &lease_id)?;
        if self
            .command_journal
            .iter()
            .any(|entry| entry.command_id == command_id)
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent command was already recorded locally".to_string(),
            ));
        }
        self.prune_terminal_journal();
        if self.command_journal.len() >= MAX_DESKTOP_AGENT_JOURNAL_ENTRIES {
            return Err(DesktopError::InvalidState(
                "desktop-agent command journal is full; terminal outcomes must be collected before another command is accepted".to_string(),
            ));
        }
        self.command_journal.push(DesktopAgentCommandJournalEntry {
            command_id,
            lease_id,
            kind,
            state: DesktopAgentCommandJournalState::Leased,
            next_event_sequence: 1,
            updated_at: now,
            terminal_code: None,
            pending_terminal_status: None,
            result_code: None,
            result: None,
            terminal_event_sequence: None,
            pending_progress_phase: None,
            pending_progress_event_sequence: None,
            abandonment_reason: None,
        });
        Ok(())
    }
}

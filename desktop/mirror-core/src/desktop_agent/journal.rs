use chrono::{DateTime, Utc};

use crate::{DesktopError, Result};

use super::{
    DesktopAgentAbandonmentReason, DesktopAgentCommandJournalState, DesktopAgentControlState,
    DesktopAgentJournalRecovery, DesktopAgentPendingProgress, DesktopAgentProgressPhase,
    DesktopAgentResultCode, DesktopAgentResultPayload, DesktopAgentTerminalCode,
    DesktopAgentTerminalStatus,
};

mod cancellation;
mod transition;
mod validation;

use transition::{JournalTerminal, JournalTransition};

impl DesktopAgentControlState {
    /// Record only an acknowledgement the broker already accepted. A command
    /// remains leased when its acknowledgement request has an unknown outcome;
    /// it must never be replayed locally.
    pub fn mark_acknowledged(&mut self, command_id: &str, now: DateTime<Utc>) -> Result<u64> {
        self.transition(command_id, JournalTransition::acknowledgement(now))
    }

    /// Read the next persisted event sequence without changing command state.
    /// The caller uses it for a network event and records its transition only
    /// once the broker has accepted that exact sequence.
    pub fn next_event_sequence(&self, command_id: &str) -> Result<u64> {
        self.command_journal
            .iter()
            .find(|entry| entry.command_id == command_id)
            .map(|entry| entry.next_event_sequence)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent command is not in the durable journal".to_string(),
                )
            })
    }

    /// Reserve the exact durable sequence for an accepted or renewal progress
    /// event. It cannot be followed by another event until the server accepts
    /// it, or the caller retries this same event after a response loss.
    pub fn begin_progress(
        &mut self,
        command_id: &str,
        phase: DesktopAgentProgressPhase,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        let entry = self
            .command_journal
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent command is not in the durable journal".to_string(),
                )
            })?;
        if !matches!(
            entry.state,
            DesktopAgentCommandJournalState::Acknowledged
                | DesktopAgentCommandJournalState::Running
        ) {
            return Err(DesktopError::InvalidState(
                "desktop-agent progress requires an acknowledged or running command".to_string(),
            ));
        }
        if entry.pending_progress_event_sequence.is_some() || entry.pending_progress_phase.is_some()
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent command already has a pending progress event".to_string(),
            ));
        }
        let sequence = entry.next_event_sequence;
        entry.next_event_sequence = entry.next_event_sequence.saturating_add(1);
        entry.state = DesktopAgentCommandJournalState::Running;
        entry.updated_at = now;
        entry.pending_progress_phase = Some(phase);
        entry.pending_progress_event_sequence = Some(sequence);
        Ok(sequence)
    }

    pub fn mark_progress_reported(
        &mut self,
        command_id: &str,
        event_sequence: u64,
        phase: DesktopAgentProgressPhase,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let entry = self
            .command_journal
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent command is not in the durable journal".to_string(),
                )
            })?;
        let expected_state = matches!(entry.state, DesktopAgentCommandJournalState::Running)
            || (entry.state == DesktopAgentCommandJournalState::RelaunchPending
                && phase == DesktopAgentProgressPhase::RelaunchPending);
        if !expected_state
            || entry.pending_progress_event_sequence != Some(event_sequence)
            || entry.pending_progress_phase != Some(phase)
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent progress acknowledgement did not match its durable request"
                    .to_string(),
            ));
        }
        entry.pending_progress_event_sequence = None;
        entry.pending_progress_phase = None;
        entry.updated_at = now;
        Ok(())
    }

    pub fn pending_progress_reports(&self) -> Result<Vec<DesktopAgentPendingProgress>> {
        self.command_journal
            .iter()
            .filter_map(|entry| {
                match (
                    entry.pending_progress_event_sequence,
                    entry.pending_progress_phase,
                ) {
                    (None, None) => None,
                    (Some(event_sequence), Some(phase)) => Some(Ok(DesktopAgentPendingProgress {
                        command_id: entry.command_id.clone(),
                        lease_id: entry.lease_id.clone(),
                        event_sequence,
                        phase,
                    })),
                    _ => Some(Err(DesktopError::InvalidState(
                        "desktop-agent progress retry fields disagree".to_string(),
                    ))),
                }
            })
            .collect()
    }

    /// Stop retrying a request that the broker has authoritatively made
    /// unrecoverable. This leaves no fabricated terminal acceptance or result.
    pub fn abandon(
        &mut self,
        command_id: &str,
        reason: DesktopAgentAbandonmentReason,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let entry = self
            .command_journal
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent command is not in the durable journal".to_string(),
                )
            })?;
        if entry.state.is_terminal() {
            return Err(DesktopError::InvalidState(
                "desktop-agent command already has a final local disposition".to_string(),
            ));
        }
        entry.state = DesktopAgentCommandJournalState::Abandoned;
        entry.updated_at = now;
        entry.terminal_code = None;
        entry.pending_terminal_status = None;
        entry.result_code = None;
        entry.result = None;
        entry.terminal_event_sequence = None;
        entry.pending_progress_phase = None;
        entry.pending_progress_event_sequence = None;
        entry.abandonment_reason = Some(reason);
        Ok(())
    }

    pub fn is_relaunch_pending(&self, command_id: &str) -> bool {
        self.command_journal.iter().any(|entry| {
            entry.command_id == command_id
                && entry.state == DesktopAgentCommandJournalState::RelaunchPending
        })
    }

    pub fn mark_relaunch_pending(&mut self, command_id: &str, now: DateTime<Utc>) -> Result<u64> {
        self.begin_relaunch_pending(command_id, now)
    }

    /// Reserve the exact re-launch progress request before the updater asks
    /// the OS to restart. A response loss retains this same sequence and phase
    /// for an idempotent retry; no later terminal can skip it.
    pub fn begin_relaunch_pending(&mut self, command_id: &str, now: DateTime<Utc>) -> Result<u64> {
        let entry = self
            .command_journal
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent command is not in the durable journal".to_string(),
                )
            })?;
        if entry.kind != super::DesktopAgentCommandKind::InstallDesktopUpdate
            || entry.state != DesktopAgentCommandJournalState::Running
            || entry.pending_progress_event_sequence.is_some()
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent relaunch requires a running update without a pending event"
                    .to_string(),
            ));
        }
        let sequence = entry.next_event_sequence;
        entry.next_event_sequence = entry.next_event_sequence.saturating_add(1);
        entry.state = DesktopAgentCommandJournalState::RelaunchPending;
        entry.updated_at = now;
        entry.pending_progress_phase = Some(DesktopAgentProgressPhase::RelaunchPending);
        entry.pending_progress_event_sequence = Some(sequence);
        Ok(sequence)
    }

    /// After the restarted binary proves its target version, turn only the
    /// matching persisted update command into an exact terminal report. The
    /// caller clears the separate restart intent only after the broker accepts
    /// this fixed success payload.
    pub fn complete_relaunched_update(
        &mut self,
        command_id: &str,
        candidate_id: String,
        installed_version: String,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let entry = self
            .command_journal
            .iter()
            .find(|entry| entry.command_id == command_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent update restart has no durable command".to_string(),
                )
            })?;
        if entry.kind != super::DesktopAgentCommandKind::InstallDesktopUpdate
            || entry.state != DesktopAgentCommandJournalState::RelaunchPending
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent update restart does not match a relaunch-pending command"
                    .to_string(),
            ));
        }
        self.mark_terminal(
            command_id,
            DesktopAgentTerminalStatus::Succeeded,
            DesktopAgentTerminalCode::Completed,
            Some(DesktopAgentResultCode::UpdateInstalled),
            Some(DesktopAgentResultPayload::UpdateInstall {
                candidate_id,
                installed_version,
            }),
            now,
        )?;
        Ok(())
    }

    pub fn mark_terminal(
        &mut self,
        command_id: &str,
        status: DesktopAgentTerminalStatus,
        terminal_code: DesktopAgentTerminalCode,
        result_code: Option<DesktopAgentResultCode>,
        result: Option<DesktopAgentResultPayload>,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        if self
            .command_journal
            .iter()
            .find(|entry| entry.command_id == command_id)
            .is_some_and(|entry| entry.pending_progress_event_sequence.is_some())
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent terminal cannot skip a pending progress event".to_string(),
            ));
        }
        let sequence = self.transition(
            command_id,
            JournalTransition::terminal(
                now,
                JournalTerminal {
                    status,
                    code: terminal_code,
                    result_code,
                    result,
                },
            ),
        )?;
        let entry = self
            .command_journal
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
            .expect("transition found the durable command");
        entry.terminal_event_sequence = Some(sequence);
        entry.abandonment_reason = None;
        self.last_terminal_command_id = Some(command_id.to_string());
        Ok(sequence)
    }

    pub fn terminal_reports(&self) -> Result<Vec<DesktopAgentJournalRecovery>> {
        self.command_journal
            .iter()
            .filter(|entry| entry.state == DesktopAgentCommandJournalState::TerminalReporting)
            .map(|entry| {
                Ok(DesktopAgentJournalRecovery {
                    command_id: entry.command_id.clone(),
                    lease_id: entry.lease_id.clone(),
                    event_sequence: entry.terminal_event_sequence.ok_or_else(|| {
                        DesktopError::InvalidState(
                            "desktop-agent terminal retry has no committed sequence".to_string(),
                        )
                    })?,
                    terminal_status: entry.pending_terminal_status.ok_or_else(|| {
                        DesktopError::InvalidState(
                            "desktop-agent terminal retry has no pending status".to_string(),
                        )
                    })?,
                    terminal_code: entry.terminal_code.ok_or_else(|| {
                        DesktopError::InvalidState(
                            "desktop-agent terminal retry has no terminal code".to_string(),
                        )
                    })?,
                    result_code: entry.result_code,
                    result: entry.result.clone(),
                })
            })
            .collect()
    }

    /// Record successful server acceptance of the already-persisted terminal
    /// event. Until this point restart recovery resends the same fixed codes.
    pub fn mark_terminal_reported(&mut self, command_id: &str, now: DateTime<Utc>) -> Result<()> {
        let entry = self
            .command_journal
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent command is not in the durable journal".to_string(),
                )
            })?;
        let status = entry.pending_terminal_status.ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent command has no pending terminal outcome".to_string(),
            )
        })?;
        entry.state = match status {
            DesktopAgentTerminalStatus::Succeeded => DesktopAgentCommandJournalState::Succeeded,
            DesktopAgentTerminalStatus::Failed => DesktopAgentCommandJournalState::Failed,
            DesktopAgentTerminalStatus::Rejected => DesktopAgentCommandJournalState::Rejected,
            DesktopAgentTerminalStatus::Interrupted => DesktopAgentCommandJournalState::Interrupted,
        };
        entry.pending_terminal_status = None;
        entry.updated_at = now;
        Ok(())
    }

    /// Atomically turn every post-ack, nonterminal entry into an interruption
    /// report. A merely leased command is not acknowledged and is deliberately
    /// left for server lease expiry/requeue.
    pub fn interrupt_after_restart(
        &mut self,
        now: DateTime<Utc>,
    ) -> Vec<DesktopAgentJournalRecovery> {
        let mut last_interrupted_command_id = None;
        for entry in &mut self.command_journal {
            if matches!(
                entry.state,
                DesktopAgentCommandJournalState::Acknowledged
                    | DesktopAgentCommandJournalState::Running
                    | DesktopAgentCommandJournalState::RelaunchPending
            ) {
                let sequence = entry.next_event_sequence;
                entry.next_event_sequence = entry.next_event_sequence.saturating_add(1);
                entry.state = DesktopAgentCommandJournalState::TerminalReporting;
                entry.pending_terminal_status = Some(DesktopAgentTerminalStatus::Interrupted);
                entry.terminal_code = Some(DesktopAgentTerminalCode::CrashUnproven);
                entry.result_code = None;
                entry.result = None;
                entry.terminal_event_sequence = Some(sequence);
                entry.pending_progress_phase = None;
                entry.pending_progress_event_sequence = None;
                entry.abandonment_reason = None;
                entry.updated_at = now;
                last_interrupted_command_id = Some(entry.command_id.clone());
            }
        }
        if let Some(command_id) = last_interrupted_command_id {
            self.last_terminal_command_id = Some(command_id);
        }
        self.terminal_reports()
            .expect("post-restart transition creates complete terminal reports")
    }

    fn transition(&mut self, command_id: &str, transition: JournalTransition) -> Result<u64> {
        let entry = self
            .command_journal
            .iter_mut()
            .find(|entry| entry.command_id == command_id)
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "desktop-agent command is not in the durable journal".to_string(),
                )
            })?;
        if entry.state.is_terminal() {
            return Err(DesktopError::InvalidState(
                "desktop-agent command already has a terminal outcome".to_string(),
            ));
        }
        let sequence = entry.next_event_sequence;
        entry.next_event_sequence = entry.next_event_sequence.saturating_add(1);
        entry.state = transition.state;
        entry.updated_at = transition.now;
        entry.terminal_code = transition.terminal.as_ref().map(|terminal| terminal.code);
        entry.pending_terminal_status =
            transition.terminal.as_ref().map(|terminal| terminal.status);
        entry.result_code = transition
            .terminal
            .as_ref()
            .and_then(|terminal| terminal.result_code);
        entry.result = transition.terminal.and_then(|terminal| terminal.result);
        entry.terminal_event_sequence = None;
        entry.pending_progress_phase = None;
        entry.pending_progress_event_sequence = None;
        entry.abandonment_reason = None;
        Ok(sequence)
    }

    pub(crate) fn prune_terminal_journal(&mut self) {
        let first_pending = self
            .command_journal
            .iter()
            .position(|entry| !entry.state.is_terminal())
            .unwrap_or(self.command_journal.len());
        if first_pending > 0 {
            self.command_journal.drain(0..first_pending);
        }
    }
}

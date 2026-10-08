//! Non-secret restart disposition for one staged credential slot.

use crate::{DesktopState, ExactCredentialRead, RemoteSessionRecord};

/// The exact non-secret locator permitted to recover an interrupted candidate.
/// A publication can have saved the active record before its staged slot is
/// enumerated, so prefer the explicit marker but retain that active fallback.
pub fn candidate_recovery_locator(state: &DesktopState) -> Option<&RemoteSessionRecord> {
    state
        .pending_candidate_session
        .as_ref()
        .or(state.active_remote_session.as_ref())
}

/// The one safe next step for a staged candidate observed during restart.
/// `CompleteActivePublication` is intentionally distinct from ordinary
/// promotion: its active locator was already saved before a crash, so a
/// canonical mismatch must not revoke that candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedCandidateRecoveryAction {
    Promote,
    CompleteActivePublication,
    Retire,
    Retain,
}

/// Classifies a staged slot using non-secret state and one exact canonical
/// readback. An active record matching the slot is a half-published candidate,
/// not an unpublished bearer to log out.
pub fn staged_candidate_recovery_action(
    state: &DesktopState,
    server_url: &str,
    email: &str,
    session_id: &str,
    canonical: ExactCredentialRead,
) -> StagedCandidateRecoveryAction {
    match canonical {
        ExactCredentialRead::Unknown => StagedCandidateRecoveryAction::Retain,
        ExactCredentialRead::Matches
            if candidate_recovery_locator(state).is_some_and(|locator| {
                !locator.identity_matches(server_url, email) || locator.session_id != session_id
            }) =>
        {
            // A different durable candidate remains authoritative. Do not
            // overwrite it merely because this stale slot matches canonical.
            StagedCandidateRecoveryAction::Retain
        }
        ExactCredentialRead::Matches => StagedCandidateRecoveryAction::Promote,
        ExactCredentialRead::DifferentOrAbsent => {
            if state.active_remote_session.as_ref().is_some_and(|active| {
                active.identity_matches(server_url, email) && active.session_id == session_id
            }) {
                StagedCandidateRecoveryAction::CompleteActivePublication
            } else {
                StagedCandidateRecoveryAction::Retire
            }
        }
    }
}

/// Builds the exact non-secret state image that must be persisted after the
/// remote server confirms retirement and before its staged bearer is deleted.
pub fn state_after_confirmed_remote_retirement(
    state: &DesktopState,
    record: &RemoteSessionRecord,
) -> DesktopState {
    let mut persisted = state.clone();
    persisted.remove_remote_session_record(record);
    persisted
}

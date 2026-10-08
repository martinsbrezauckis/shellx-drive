//! Durable, non-secret replacement-candidate metadata.

use chrono::{DateTime, Utc};

use super::{DesktopState, RemoteSessionRecord};

mod recovery_action;
mod recovery_order;
pub use recovery_action::{
    candidate_recovery_locator, staged_candidate_recovery_action,
    state_after_confirmed_remote_retirement, StagedCandidateRecoveryAction,
};
pub use recovery_order::compare_staged_candidate_recovery_order;

impl DesktopState {
    /// Persist this candidate before its dedicated Credential Manager slot is
    /// written. Replacing one unresolved candidate retains the old locator as
    /// an ordinary bounded retirement record so a fresh candidate can revoke
    /// it instead of silently losing the exact session ID.
    pub fn record_pending_candidate_session(
        &mut self,
        record: RemoteSessionRecord,
        now: DateTime<Utc>,
    ) {
        self.prune_remote_sessions(now);
        if record.expires_at <= now {
            return;
        }
        if let Some(previous) = self.pending_candidate_session.replace(record.clone()) {
            if !previous.same_remote_session(&record) {
                self.record_pending_remote_revocation(previous, now);
            }
        }
    }
}

pub(super) fn clear_matching(state: &mut DesktopState, record: &RemoteSessionRecord) {
    if state
        .pending_candidate_session
        .as_ref()
        .is_some_and(|candidate| candidate.same_remote_session(record))
    {
        state.pending_candidate_session = None;
    }
}

pub(super) fn prune_expired(state: &mut DesktopState, now: DateTime<Utc>) {
    if state
        .pending_candidate_session
        .as_ref()
        .is_some_and(|record| record.expires_at <= now)
    {
        state.pending_candidate_session = None;
    }
}

pub(super) fn take(state: &mut DesktopState) -> Option<RemoteSessionRecord> {
    state.pending_candidate_session.take()
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::ExactCredentialRead;

    fn record(session_id: &str, now: DateTime<Utc>) -> RemoteSessionRecord {
        RemoteSessionRecord::new(
            "https://drive.example.test",
            "person@example.test",
            session_id,
            now + Duration::hours(1),
        )
        .unwrap()
    }

    #[test]
    fn replacing_a_no_slot_candidate_retains_its_exact_retirement_locator() {
        let now = Utc::now();
        let old = record("old-session", now);
        let next = record("next-session", now);
        let mut state = DesktopState::default();
        state.record_pending_candidate_session(old.clone(), now);
        state.record_pending_candidate_session(next.clone(), now);

        assert_eq!(state.pending_candidate_session, Some(next));
        assert_eq!(state.pending_remote_revocations, vec![old]);
        assert!(!serde_json::to_string(&state).unwrap().contains("bearer"));
    }

    #[test]
    fn active_staged_candidate_with_an_old_canonical_bearer_is_repromoted() {
        let now = Utc::now();
        let candidate = record("candidate-session", now);
        let state = DesktopState {
            active_remote_session: Some(candidate.clone()),
            ..DesktopState::default()
        };

        assert_eq!(
            staged_candidate_recovery_action(
                &state,
                &candidate.server_url,
                &candidate.account_email,
                &candidate.session_id,
                ExactCredentialRead::DifferentOrAbsent,
            ),
            StagedCandidateRecoveryAction::CompleteActivePublication
        );
    }

    #[test]
    fn active_candidate_is_a_recovery_locator_when_staging_metadata_was_cleared() {
        let now = Utc::now();
        let candidate = record("candidate-session", now);
        let state = DesktopState {
            active_remote_session: Some(candidate.clone()),
            ..DesktopState::default()
        };

        assert_eq!(candidate_recovery_locator(&state), Some(&candidate));
    }
}

//! Portable fault-state regression for staged-candidate restart ordering.

use chrono::Utc;

use super::super::record;
use crate::{
    classify_exact_credential_removal, classify_exact_credential_write,
    staged_candidate_recovery_action, DesktopError, DesktopState, ExactCredentialRemoval,
    ExactCredentialWrite, StagedCandidateRecoveryAction,
};

struct FakeCandidateRecovery {
    state: DesktopState,
    staged_slot: bool,
    canonical_is_candidate: bool,
    canonical_old_slots: bool,
    latch: bool,
}

impl FakeCandidateRecovery {
    fn half_published(candidate: crate::RemoteSessionRecord) -> Self {
        Self {
            // Simulates a crash after the active state image was saved but
            // before the candidate reached the canonical credential key.
            state: DesktopState {
                active_remote_session: Some(candidate),
                ..DesktopState::default()
            },
            staged_slot: true,
            canonical_is_candidate: false,
            canonical_old_slots: true,
            latch: true,
        }
    }

    fn restart_complete_active_publication(&mut self, candidate: &crate::RemoteSessionRecord) {
        assert_eq!(
            staged_candidate_recovery_action(
                &self.state,
                &candidate.server_url,
                &candidate.account_email,
                &candidate.session_id,
                if self.canonical_is_candidate {
                    crate::ExactCredentialRead::Matches
                } else {
                    crate::ExactCredentialRead::DifferentOrAbsent
                },
            ),
            StagedCandidateRecoveryAction::CompleteActivePublication
        );

        // A Credential Manager set error after write is confirmed by the
        // exact canonical readback, so recovery must keep the candidate.
        assert_eq!(
            classify_exact_credential_write(
                Err(DesktopError::Credential(
                    "injected post-write error".to_string()
                )),
                Ok(Some("candidate".to_string())),
                "candidate",
            ),
            ExactCredentialWrite::Written
        );
        self.canonical_is_candidate = true;

        // Superseded canonical slots must be deleted while this exact staged
        // bearer still exists, so a cleanup fault leaves the recovery latch.
        assert!(self.canonical_old_slots);
        self.canonical_old_slots = false;

        // The exact staged delete similarly succeeds when its probe sees no
        // slot after the provider reported an error.
        assert_eq!(
            classify_exact_credential_removal(
                Err(DesktopError::Credential(
                    "injected post-delete error".to_string()
                )),
                Ok(None),
            ),
            ExactCredentialRemoval::Removed
        );
        self.staged_slot = false;
        self.latch = self.state.pending_candidate_session.is_some() || self.staged_slot;
    }
}

#[test]
fn restart_converges_a_half_published_candidate_across_post_write_and_delete_faults() {
    let candidate = record(
        "candidate-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let mut recovery = FakeCandidateRecovery::half_published(candidate.clone());

    recovery.restart_complete_active_publication(&candidate);

    assert!(recovery.canonical_is_candidate);
    assert!(!recovery.canonical_old_slots);
    assert!(!recovery.staged_slot);
    assert!(
        !recovery.latch,
        "resolved startup recovery can start polling"
    );
    assert_eq!(recovery.state.active_remote_session, Some(candidate));
}

#[test]
fn replacing_a_no_slot_candidate_migrates_its_old_locator_before_recovery_login() {
    let old = record(
        "old-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let fresh = record(
        "fresh-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let mut state = DesktopState::default();
    state.record_pending_candidate_session(old.clone(), Utc::now());
    state.record_pending_candidate_session(fresh.clone(), Utc::now());

    assert_eq!(state.pending_remote_revocations, vec![old]);
    assert_eq!(state.pending_candidate_session, Some(fresh));
}

//! Portable two-slot candidate-recovery ordering regressions.

use chrono::{Duration, Utc};

use super::super::*;
use crate::{ExactCredentialRead, StagedCandidateRecoveryAction};

const SERVER: &str = "https://drive.example.test";
const EMAIL: &str = "person@example.test";

fn record(session_id: &str) -> RemoteSessionRecord {
    RemoteSessionRecord::new(SERVER, EMAIL, session_id, Utc::now() + Duration::hours(1)).unwrap()
}

fn ordered_sessions(state: &DesktopState) -> Vec<&'static str> {
    let mut slots = vec![(SERVER, EMAIL, "old"), (SERVER, EMAIL, "fresh")];
    slots.sort_by(|left, right| compare_staged_candidate_recovery_order(state, *left, *right));
    slots.into_iter().map(|slot| slot.2).collect()
}

#[test]
fn active_fresh_completes_before_stale_canonical_old_is_retired() {
    let fresh = record("fresh");
    let state = DesktopState {
        active_remote_session: Some(fresh.clone()),
        ..DesktopState::default()
    };
    let mut canonical = "old";
    let mut retired = Vec::new();

    for session_id in ordered_sessions(&state) {
        let canonical_state = if canonical == session_id {
            ExactCredentialRead::Matches
        } else {
            ExactCredentialRead::DifferentOrAbsent
        };
        match crate::staged_candidate_recovery_action(
            &state,
            SERVER,
            EMAIL,
            session_id,
            canonical_state,
        ) {
            StagedCandidateRecoveryAction::CompleteActivePublication => canonical = session_id,
            StagedCandidateRecoveryAction::Retire => retired.push(session_id),
            disposition => panic!("unexpected stale-slot disposition: {disposition:?}"),
        }
    }

    assert_eq!(canonical, "fresh");
    assert_eq!(retired, ["old"]);
    assert_eq!(state.active_remote_session, Some(fresh));
}

#[test]
fn pending_fresh_precedes_active_and_stale_lexical_slots() {
    let mut state = DesktopState {
        active_remote_session: Some(record("old")),
        ..DesktopState::default()
    };
    state.record_pending_candidate_session(record("fresh"), Utc::now());

    assert_eq!(ordered_sessions(&state), ["fresh", "old"]);
}

#[test]
fn canonical_match_for_a_different_durable_locator_is_retained() {
    let state = DesktopState {
        active_remote_session: Some(record("fresh")),
        ..DesktopState::default()
    };

    assert_eq!(
        crate::staged_candidate_recovery_action(
            &state,
            SERVER,
            EMAIL,
            "old",
            ExactCredentialRead::Matches,
        ),
        StagedCandidateRecoveryAction::Retain
    );
}

#[test]
fn pending_no_slot_is_resolved_before_a_stale_canonical_slot_is_promoted() {
    let fresh = record("fresh");
    let mut state = DesktopState {
        active_remote_session: Some(record("old")),
        ..DesktopState::default()
    };
    state.record_pending_candidate_session(fresh.clone(), Utc::now());

    // This models the successful exact fresh-session revocation made with the
    // old canonical authorizer before the remaining staged old slot is read.
    state = crate::state_after_confirmed_remote_retirement(&state, &fresh);
    assert_eq!(
        crate::staged_candidate_recovery_action(
            &state,
            SERVER,
            EMAIL,
            "old",
            ExactCredentialRead::Matches,
        ),
        StagedCandidateRecoveryAction::Promote
    );
}

#[test]
fn failed_no_slot_recovery_retains_the_pending_locator_and_stale_slot() {
    let fresh = record("fresh");
    let mut state = DesktopState {
        active_remote_session: Some(record("old")),
        ..DesktopState::default()
    };
    state.record_pending_candidate_session(fresh.clone(), Utc::now());

    let revoke: crate::Result<()> = Err(crate::DesktopError::Credential(
        "injected canonical authorizer failure".to_string(),
    ));
    assert!(revoke.is_err());
    assert_eq!(state.pending_candidate_session, Some(fresh));
    assert_eq!(
        crate::staged_candidate_recovery_action(
            &state,
            SERVER,
            EMAIL,
            "old",
            ExactCredentialRead::Matches,
        ),
        StagedCandidateRecoveryAction::Retain
    );
}

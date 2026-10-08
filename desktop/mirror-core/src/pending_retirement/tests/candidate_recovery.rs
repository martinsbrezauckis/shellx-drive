//! Regression for recovery login after a candidate write failed before a slot.

use chrono::Utc;

use super::{matches, record, Authorizer};
use crate::{confirm_pending_remote_retirements, DesktopState, RemoteSessionRevocationOutcome};

mod active_locator;
mod faults;
mod retirement_order;

#[test]
fn same_identity_recovery_candidate_retires_the_retained_no_slot_session() {
    let old = record(
        "old-no-slot-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let fresh = record(
        "fresh-recovery-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let mut state = DesktopState::default();
    // The original candidate has no Credential Manager slot after a
    // post-write/read ambiguity. Starting the exact same-identity login must
    // retain its locator while staging the fresh candidate.
    state.record_pending_candidate_session(old.clone(), Utc::now());
    state.record_pending_candidate_session(fresh.clone(), Utc::now());
    assert_eq!(state.pending_remote_revocations, vec![old.clone()]);

    let fresh_authorizer = Authorizer {
        label: "fresh-recovery-authorizer",
        server_url: "https://drive.example.test",
        email: "person@example.test",
    };
    let selected = super::super::select_pending_retirement_authorizer(
        &old,
        Some(&fresh_authorizer),
        &[],
        matches,
    )
    .expect("the exact same-identity recovery login authorizes old-session retirement");
    assert_eq!(selected.label, "fresh-recovery-authorizer");
    confirm_pending_remote_retirements([(
        old.clone(),
        Ok(RemoteSessionRevocationOutcome::Revoked),
    )])
    .unwrap();
    state.remove_remote_session_record(&old);

    assert!(state.pending_remote_revocations.is_empty());
    assert_eq!(state.pending_candidate_session, Some(fresh));
}

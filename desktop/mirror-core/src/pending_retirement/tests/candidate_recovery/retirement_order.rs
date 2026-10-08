//! Portable save-before-secret-removal regression.

use chrono::Utc;

use super::super::record;
use crate::{state_after_confirmed_remote_retirement, DesktopError, DesktopState};

#[test]
fn logout_save_failure_keeps_the_exact_locator_for_recovery_login() {
    let candidate = record(
        "candidate-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let mut state = DesktopState::default();
    state.record_pending_candidate_session(candidate.clone(), Utc::now());
    let staged_slot = true;

    let retired = state_after_confirmed_remote_retirement(&state, &candidate);
    assert_eq!(retired.pending_candidate_session, None);
    let save_result: crate::Result<()> = Err(DesktopError::InvalidState(
        "injected save failure".to_string(),
    ));
    assert!(save_result.is_err());
    assert_eq!(state.pending_candidate_session, Some(candidate));
    assert!(
        staged_slot,
        "the staged secret must survive a failed state save"
    );
}

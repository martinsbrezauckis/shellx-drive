use super::record;
use crate::{
    confirm_direct_retirement, confirm_remote_retirement,
    pending_record_requires_authorized_retirement, DesktopError, DesktopState, LogoutOutcome,
};

#[test]
fn partial_direct_logout_keeps_the_remaining_session_for_retry() {
    let first = record(
        "first-current-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let second = record(
        "second-current-session",
        "https://second.example.test",
        "second@example.test",
    );
    let mut durable = DesktopState {
        pending_remote_revocations: vec![first.clone(), second.clone()],
        ..DesktopState::default()
    };

    confirm_remote_retirement(["first-bearer"], |_| Ok(LogoutOutcome::Revoked)).unwrap();
    durable.remove_remote_session_record(&first);
    // This models the per-bearer durable write completing before the next
    // logout is attempted. The second failure must not erase its retry record.
    let error = confirm_remote_retirement(["second-bearer"], |_| {
        Err(DesktopError::InvalidState(
            "temporary network failure".to_string(),
        ))
    })
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "credential store error: remote session retirement was not confirmed; credentials were kept for retry"
    );
    assert_eq!(durable.pending_remote_revocations, vec![second.clone()]);

    let direct_retirements = [second.clone()];
    assert!(!pending_record_requires_authorized_retirement(
        &second,
        None,
        &direct_retirements
    ));
    confirm_remote_retirement(["second-bearer"], |_| Ok(LogoutOutcome::Revoked)).unwrap();
    durable.remove_remote_session_record(&second);

    assert!(durable.pending_remote_revocations.is_empty());
}

#[test]
fn failed_cross_identity_direct_logout_blocks_candidate_publication() {
    let old_session = record(
        "old-other-account-session",
        "https://second.example.test",
        "second@example.test",
    );
    let retained_state = DesktopState {
        pending_remote_revocations: vec![old_session.clone()],
        ..DesktopState::default()
    };

    let result = confirm_direct_retirement(
        Some(old_session.clone()),
        Err(DesktopError::InvalidState(
            "temporary network failure".to_string(),
        )),
    );
    assert!(result.is_err());
    // Replacement publication is gated on this confirmation, so the candidate
    // cannot replace the only cross-identity authorizer after this failure.
    assert_eq!(retained_state.pending_remote_revocations, vec![old_session]);
    assert_eq!(
        result.unwrap_err().to_string(),
        "credential store error: remote session retirement was not confirmed; credentials were kept for retry"
    );
}

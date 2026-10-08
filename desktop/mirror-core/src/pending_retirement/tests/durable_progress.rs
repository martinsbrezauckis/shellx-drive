use super::{matches, record, Authorizer};
use crate::{
    confirm_pending_remote_retirements, confirm_remote_retirement,
    pending_record_requires_authorized_retirement, DesktopState, LogoutOutcome,
    RemoteSessionRevocationOutcome,
};

#[test]
fn cross_identity_pending_session_drains_before_its_fallback_is_logged_out() {
    let pending = record(
        "older-account-b-session",
        "https://second.example.test",
        "second@example.test",
    );
    let direct_bearer_session = record(
        "current-account-b-session",
        "https://second.example.test",
        "second@example.test",
    );
    let candidate = Authorizer {
        label: "fresh-other-account",
        server_url: "https://drive.example.test",
        email: "person@example.test",
    };
    let fallback = Authorizer {
        label: "live-account-b-bearer",
        server_url: "https://second.example.test",
        email: "second@example.test",
    };
    let direct_retirements = [direct_bearer_session.clone()];

    assert!(pending_record_requires_authorized_retirement(
        &pending,
        None,
        &direct_retirements
    ));
    let retained = [fallback];
    let authorizer = super::super::select_pending_retirement_authorizer(
        &pending,
        Some(&candidate),
        &retained,
        matches,
    )
    .expect("the still-live matching bearer must revoke the older session first");
    assert_eq!(authorizer.label, "live-account-b-bearer");
    let retired = confirm_pending_remote_retirements([(
        pending.clone(),
        Ok(RemoteSessionRevocationOutcome::Revoked),
    )])
    .unwrap();
    assert_eq!(retired, [pending]);

    assert!(!pending_record_requires_authorized_retirement(
        &direct_bearer_session,
        None,
        &direct_retirements
    ));
}

#[test]
fn save_failure_after_direct_logout_retries_without_stale_session_revocation() {
    let direct_session = record(
        "current-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let direct_retirements = [direct_session.clone()];
    let persisted = DesktopState {
        active_remote_session: Some(direct_session.clone()),
        ..DesktopState::default()
    };

    assert!(!pending_record_requires_authorized_retirement(
        &direct_session,
        None,
        &direct_retirements
    ));
    confirm_remote_retirement(["old-bearer"], |_| Ok(LogoutOutcome::Revoked)).unwrap();

    // A failed save leaves the pre-logout state on disk. A retry must repeat
    // direct logout (which accepts the invalid bearer) rather than use it as a
    // session-revocation authorizer for the stale record.
    let mut retry = persisted.clone();
    let retry_direct = [retry.active_remote_session.clone().unwrap()];
    assert!(!pending_record_requires_authorized_retirement(
        retry.active_remote_session.as_ref().unwrap(),
        None,
        &retry_direct
    ));
    confirm_remote_retirement(["old-bearer"], |_| Ok(LogoutOutcome::AlreadyInvalid)).unwrap();
    retry.remove_remote_session_record(&direct_session);

    assert!(retry.active_remote_session.is_none());
    assert!(retry.pending_remote_revocations.is_empty());
}

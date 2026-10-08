use super::*;
use chrono::Utc;
use shellx_drive_desktop_core::RemoteSessionRecord;

fn record(email: &str, session_id: &str) -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        "https://drive.example.test",
        email,
        session_id,
        Utc::now() + chrono::Duration::hours(1),
    )
    .unwrap()
}

fn key(email: &str, session_id: &str) -> String {
    SessionIdentity::new("https://drive.example.test", email)
        .pending_service_key(session_id)
        .unwrap()
        .account_key
}

#[test]
fn other_account_and_same_account_unowned_candidates_do_not_enter_recovery() {
    let state = DesktopState {
        pending_candidate_session: Some(record("work@example.test", "work-session")),
        pending_remote_revocations: vec![record("work@example.test", "older-owned")],
        ..DesktopState::default()
    };
    let keys = vec![
        key("personal@example.test", "personal-session"),
        key("work@example.test", "rejected-duplicate"),
        "unattributed malformed legacy slot".to_string(),
        key("work@example.test", "work-session"),
        key("work@example.test", "older-owned"),
    ];
    assert_eq!(
        filter_owned_pending_keys(&state, keys),
        vec![
            key("work@example.test", "work-session"),
            key("work@example.test", "older-owned"),
        ]
    );
}

#[test]
fn empty_runtime_does_not_adopt_any_pending_candidate() {
    assert!(filter_owned_pending_keys(
        &DesktopState::default(),
        vec![key("person@example.test", "unowned"),]
    )
    .is_empty());
}

#[test]
fn missing_staged_bearer_on_restart_allows_only_the_retained_identity_to_sign_in() {
    let directory = tempfile::tempdir().unwrap();
    let store = shellx_drive_desktop_core::StateStore::new(directory.path().join("state.json"));
    let state = DesktopState {
        pending_candidate_session: Some(record("work@example.test", "deleted-after-retirement")),
        ..DesktopState::default()
    };
    store.save(&state).unwrap();
    let restarted = store.load().unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(crate::application::runtime::tests::TestPlatform(
            shellx_drive_desktop_core::FakeCredentialStore::default(),
        )),
        store,
        restarted,
    );
    runtime.set_candidate_recovery_pending(true);
    assert!(runtime.require_candidate_recovery_complete().is_err());
    runtime
        .require_linux_candidate_recovery_identity(
            "https://drive.example.test",
            "work@example.test",
        )
        .unwrap();
    assert!(runtime
        .require_linux_candidate_recovery_identity(
            "https://drive.example.test",
            "other@example.test",
        )
        .is_err());
    assert!(runtime
        .require_linux_candidate_recovery_identity(
            "https://another.example.test",
            "work@example.test",
        )
        .is_err());
}

use shellx_drive_desktop_core::{DesktopState, FakeCredentialStore, StateStore};

use super::{tests::TestPlatform, Runtime};

#[test]
fn active_update_intent_waits_for_an_unconfirmed_startup_readback() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let mut state = DesktopState::default();
    state
        .record_desktop_update_restart("99.99.99".to_string(), "candidate-1".to_string())
        .expect("active human update intent");
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );

    assert_eq!(runtime.update_recovery_target_version(), None);
    crate::application::update_service::reconcile_desktop_update_restart(&runtime)
        .expect("startup update reconciliation");
    assert_eq!(
        runtime.update_recovery_target_version().as_deref(),
        Some("99.99.99")
    );

    let mut agent_state = DesktopState::default();
    agent_state
        .record_desktop_update_restart_for_agent(
            "98.98.98".to_string(),
            "candidate-2".to_string(),
            "command-1".to_string(),
        )
        .expect("active agent update intent");
    let agent_runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("agent-state.json")),
        agent_state,
    );
    crate::application::update_service::reconcile_desktop_update_restart(&agent_runtime)
        .expect("agent startup reconciliation");
    assert_eq!(agent_runtime.update_recovery_target_version(), None);
}

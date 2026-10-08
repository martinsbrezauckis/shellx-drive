use shellx_drive_desktop_core::{DesktopState, FakeCredentialStore, StateStore};

use super::persist_restart_intent;
use crate::application::{
    runtime::{tests::TestPlatform, Runtime},
    update_service::reconcile_desktop_update_restart,
};

#[test]
fn rejected_retry_persistence_retains_the_prior_startup_recovery_notice() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let blocked_parent = directory.path().join("blocked-state-parent");
    std::fs::write(&blocked_parent, b"fixture").expect("regular blocked state parent");

    let mut state = DesktopState::default();
    state
        .record_desktop_update_restart("99.99.99".to_string(), "candidate-1".to_string())
        .expect("prior human update intent");
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(blocked_parent.join("state.json")),
        state,
    );
    reconcile_desktop_update_restart(&runtime).expect("startup reconciliation");
    assert_eq!(
        runtime.update_recovery_target_version().as_deref(),
        Some("99.99.99")
    );

    assert!(persist_restart_intent(&runtime, "98.98.98", "candidate-2", None).is_err());
    assert_eq!(
        runtime.update_recovery_target_version().as_deref(),
        Some("99.99.99")
    );
}

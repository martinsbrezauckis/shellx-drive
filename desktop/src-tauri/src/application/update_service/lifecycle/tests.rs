use shellx_drive_desktop_core::{DesktopState, FakeCredentialStore, StateStore};

use super::persist_restart_intent;
use crate::application::{
    runtime::{tests::TestPlatform, Runtime},
    update_service::reconcile_desktop_update_restart,
};

#[test]
fn accepted_human_or_agent_update_retry_clears_the_prior_startup_recovery_notice() {
    for (label, agent_command_id) in [("human", None), ("agent", Some("agent-command-2"))] {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let mut state = DesktopState::default();
        state
            .record_desktop_update_restart("99.99.99".to_string(), "candidate-1".to_string())
            .expect("prior human update intent");
        let runtime = Runtime::from_loaded_state(
            Box::new(TestPlatform(FakeCredentialStore::default())),
            StateStore::new(directory.path().join("state.json")),
            state,
        );
        reconcile_desktop_update_restart(&runtime).expect("startup reconciliation");
        assert_eq!(
            runtime.update_recovery_target_version().as_deref(),
            Some("99.99.99"),
            "{label} retry starts from the prior recovery notice"
        );

        let _retry = persist_restart_intent(&runtime, "98.98.98", "candidate-2", agent_command_id)
            .expect("accepted retry intent");
        assert_eq!(
            runtime.update_recovery_target_version(),
            None,
            "{label} retry clears the stale recovery notice only after persisting"
        );
    }
}

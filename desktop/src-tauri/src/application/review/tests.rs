use shellx_drive_desktop_core::{
    DesktopState, FakeCredentialStore, Result as CoreResult, StateStore,
};

use super::*;

#[path = "tests/native_confirmation.rs"]
mod native_confirmation;

pub(super) struct TestPlatform(pub(super) FakeCredentialStore);

impl crate::platform::PlatformServices for TestPlatform {
    fn credentials(&self) -> &dyn shellx_drive_desktop_core::CredentialStore {
        &self.0
    }

    fn desktop_agent_credentials(&self) -> &dyn shellx_drive_desktop_core::CredentialStore {
        &self.0
    }

    fn desktop_agent_disconnect_credentials(
        &self,
    ) -> &dyn shellx_drive_desktop_core::CredentialStore {
        &self.0
    }

    fn set_launch_at_login(&self, _: bool) -> CoreResult<()> {
        Ok(())
    }

    fn open_local_root(&self, _: &std::path::Path) -> CoreResult<()> {
        Ok(())
    }

    fn open_drive_url(&self, _: &str) -> CoreResult<()> {
        Ok(())
    }
}

#[test]
fn candidate_recovery_blocks_review_confirmation_before_any_executor() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        DesktopState::default(),
    );
    runtime.set_candidate_recovery_pending(true);

    let error = prepare_review_confirmation(
        &runtime,
        "not-reached".to_string(),
        ReviewAction::RemoveLocalCopy,
    )
    .expect_err("candidate recovery must fail closed");

    assert!(error.to_string().contains("credential recovery"));
}

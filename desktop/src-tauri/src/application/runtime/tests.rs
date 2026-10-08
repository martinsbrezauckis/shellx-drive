use std::path::Path;

use chrono::Utc;
use shellx_drive_desktop_core::{
    CredentialStore, DesktopState, FakeCredentialStore, StateStore, SyncPair, SyncStatus,
};

use super::*;
use crate::session_identity::SessionIdentity;

pub(crate) struct TestPlatform(pub(crate) FakeCredentialStore);

impl crate::platform::PlatformServices for TestPlatform {
    fn credentials(&self) -> &dyn CredentialStore {
        &self.0
    }

    fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
        &self.0
    }

    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
        &self.0
    }

    fn set_launch_at_login(&self, _: bool) -> CoreResult<()> {
        Ok(())
    }

    fn open_local_root(&self, _: &Path) -> CoreResult<()> {
        Ok(())
    }

    fn open_drive_url(&self, _: &str) -> CoreResult<()> {
        Ok(())
    }
}

#[test]
fn status_and_location_projection_are_platform_neutral() {
    assert_eq!(status_code(SyncStatus::NeedsReview), "needs_review");
    assert_eq!(
        host_label("https://drive.example.test/path"),
        "drive.example.test"
    );
    assert_eq!(pair_location_label(&pair()), "Shared work / Reports");
}

#[test]
fn retained_candidate_latch_suppresses_synced_runtime_status() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let credentials = FakeCredentialStore::default();
    let identity = SessionIdentity::new("https://drive.example.test", "person@example.test");
    credentials
        .set(&identity.credential_key(), "test-bearer")
        .unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(credentials)),
        StateStore::new(directory.path().join("state.json")),
        DesktopState {
            pair: Some(pair()),
            last_successful_sync: Some(Utc::now()),
            ..DesktopState::default()
        },
    );

    assert_eq!(runtime.status(), SyncStatus::Synced);
    runtime.set_candidate_recovery_pending(true);
    assert_eq!(runtime.status(), SyncStatus::Error);
    assert!(runtime.require_candidate_recovery_complete().is_err());
}

#[test]
fn desktop_view_keeps_an_inactive_root_error_visible_for_location_search() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let mut failing = pair();
    failing.workspace_id = "failing-workspace".to_string();
    failing.workspace_name = "Failing shared root".to_string();
    failing.local_root = directory.path().join("failing-root");
    let mut selected = pair();
    selected.workspace_id = "selected-workspace".to_string();
    selected.workspace_name = "Selected root".to_string();
    selected.local_root = directory.path().join("selected-root");
    let mut state = DesktopState::default();
    state.configure_pair(failing).expect("failing root");
    state.configure_pair(selected).expect("selected root");
    state.inactive_pairs[0].last_error = Some("fixture inactive-root failure".to_string());
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );

    let view = runtime.view();
    let failed = view
        .sync_locations
        .iter()
        .find(|location| location.drive_location == "Failing shared root / Reports")
        .expect("inactive root projection");
    assert_eq!(failed.sync_status, "error");
    assert_eq!(
        failed.error.as_deref(),
        Some("fixture inactive-root failure")
    );
}

fn pair() -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Shared work".to_string(),
        remote_root_id: Some("folder".to_string()),
        remote_root_name: Some("Reports".to_string()),
        local_root: std::path::PathBuf::from("Drive"),
        local_root_identity: None,
    }
}

use shellx_drive_desktop_core::{DesktopState, FakeCredentialStore, StateStore, SyncPair};

use super::recover_unfinished_commands;
use crate::application::{runtime::tests::TestPlatform, Runtime};

#[test]
fn empty_recovery_does_not_reserve_lifecycle_during_an_active_sync() {
    let directory = tempfile::tempdir().unwrap();
    let state = DesktopState {
        pair: Some(SyncPair {
            server_url: "https://drive.example.test".to_string(),
            account_email: "person@example.test".to_string(),
            workspace_id: "workspace".to_string(),
            workspace_name: "Workspace".to_string(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: directory.path().join("Drive"),
            local_root_identity: None,
        }),
        ..DesktopState::default()
    };
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    let run = runtime.coordinator.begin_run().unwrap();

    tauri::async_runtime::block_on(recover_unfinished_commands(&runtime)).unwrap();
    assert!(run.ensure_not_cancelled().is_ok());
}

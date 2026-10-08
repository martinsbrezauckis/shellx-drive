use shellx_drive_desktop_core::{
    DesktopState, DisconnectCleanupIntent, FakeCredentialStore, StateStore,
};

use super::{tests::TestPlatform, Runtime};

fn pending_disconnect_runtime() -> (tempfile::TempDir, Runtime) {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let state = DesktopState {
        pending_disconnect_cleanup: Some(
            DisconnectCleanupIntent::for_disconnect(None, Vec::new()).expect("cleanup intent"),
        ),
        ..DesktopState::default()
    };
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    (directory, runtime)
}

#[test]
fn pending_disconnect_cleanup_blocks_shared_lifecycle_work_before_discovery() {
    let (_directory, runtime) = pending_disconnect_runtime();
    let error = runtime
        .ensure_disconnect_cleanup_complete()
        .expect_err("pending cleanup must stop lifecycle work");
    assert!(error
        .to_string()
        .contains("Disconnect local cleanup is pending"));
}

#[test]
fn pending_disconnect_cleanup_blocks_lifecycle_preference_mutations() {
    let (_directory, runtime) = pending_disconnect_runtime();
    let error = tauri::async_runtime::block_on(
        crate::application::lifecycle::persist_paused_state(&runtime, true),
    )
    .expect_err("pending cleanup must freeze lifecycle preference mutations");

    assert!(error
        .to_string()
        .contains("Disconnect local cleanup is pending"));
    assert!(!runtime.coordinator.snapshot().paused);
}

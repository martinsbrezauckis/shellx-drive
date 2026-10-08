use std::fs;

use shellx_drive_desktop_core::{DesktopState, FakeCredentialStore, StateStore};

use super::super::{
    lifecycle::persist_restart_intent, slot::UpdateSlot, DesktopUpdateService,
    DesktopUpdateServiceError,
};
use crate::application::runtime::{tests::TestPlatform, Runtime};

const CANDIDATE_ID: &str = "candidate-1";

fn runtime(state_path: std::path::PathBuf) -> Runtime {
    Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(state_path),
        DesktopState::default(),
    )
}

fn installing_service() -> DesktopUpdateService {
    let service = DesktopUpdateService::default();
    *service.lock().expect("update slot") = UpdateSlot::Installing;
    service
}

fn assert_installing_slot_is_released(service: &DesktopUpdateService) {
    assert!(matches!(
        *service.lock().expect("update slot"),
        UpdateSlot::Empty
    ));
}

#[test]
fn abort_releases_installing_slot_when_state_save_fails() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let state_path = directory.path().join("state.json");
    let runtime = runtime(state_path.clone());
    let mut lifecycle = persist_restart_intent(&runtime, "99.99.99", CANDIDATE_ID, None)
        .expect("persisted restart intent");
    let service = installing_service();

    fs::remove_file(&state_path).expect("replace saved state with a directory");
    fs::create_dir(&state_path).expect("actual StateStore persist failure fixture");

    let error = service
        .abort(
            &runtime,
            &mut lifecycle,
            CANDIDATE_ID,
            DesktopUpdateServiceError::Updater("download fixture failed".to_string()),
        )
        .expect_err("StateStore failure reaches the caller");
    assert!(matches!(error, DesktopUpdateServiceError::Lifecycle(_)));
    assert_installing_slot_is_released(&service);
    assert!(
        runtime
            .coordinator
            .snapshot()
            .pending_desktop_update_restart
            .is_some(),
        "the last durable restart intent remains available for recovery after a failed save"
    );
    assert!(matches!(
        service.take_ready(CANDIDATE_ID),
        Err(DesktopUpdateServiceError::NoCheckedUpdate)
    ));
}

#[test]
fn abort_persists_cancellation_then_returns_the_original_update_error() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let state_path = directory.path().join("state.json");
    let runtime = runtime(state_path.clone());
    let mut lifecycle = persist_restart_intent(&runtime, "99.99.99", CANDIDATE_ID, None)
        .expect("persisted restart intent");
    let service = installing_service();

    let error = service
        .abort(
            &runtime,
            &mut lifecycle,
            CANDIDATE_ID,
            DesktopUpdateServiceError::Updater("download fixture failed".to_string()),
        )
        .expect_err("the original update failure is returned");
    assert!(matches!(
        error,
        DesktopUpdateServiceError::Updater(message) if message == "download fixture failed"
    ));
    assert_installing_slot_is_released(&service);
    assert!(runtime
        .store
        .load()
        .expect("persisted cancellation")
        .pending_desktop_update_restart
        .is_none());
}

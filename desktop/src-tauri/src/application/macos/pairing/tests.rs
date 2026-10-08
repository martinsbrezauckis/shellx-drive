use std::{
    path::Path,
    sync::{atomic::Ordering, Arc, Mutex},
};

use shellx_drive_desktop_core::{
    CredentialStore, DesktopError, DesktopState, FakeCredentialStore, Result as CoreResult,
    StateStore,
};

use super::{pairing::enable_launch_at_login_after_pair, Runtime};

struct RollbackFailingPlatform {
    credentials: FakeCredentialStore,
    calls: Arc<Mutex<Vec<bool>>>,
}

impl crate::platform::PlatformServices for RollbackFailingPlatform {
    fn credentials(&self) -> &dyn CredentialStore {
        &self.credentials
    }

    fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
        &self.credentials
    }

    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
        &self.credentials
    }

    fn set_launch_at_login(&self, enabled: bool) -> CoreResult<()> {
        self.calls.lock().expect("autostart calls").push(enabled);
        if enabled {
            Ok(())
        } else {
            Err(DesktopError::InvalidState(
                "fixture rollback failed".to_string(),
            ))
        }
    }

    fn open_local_root(&self, _: &Path) -> CoreResult<()> {
        Ok(())
    }

    fn open_drive_url(&self, _: &str) -> CoreResult<()> {
        Ok(())
    }
}

#[test]
fn pairing_retains_rollback_repair_error_and_stops_before_sync() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let not_a_directory = directory.path().join("state-parent");
    std::fs::write(&not_a_directory, b"regular file blocks state directory")
        .expect("fixture state parent");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let runtime = Runtime::from_loaded_state(
        Box::new(RollbackFailingPlatform {
            credentials: FakeCredentialStore::default(),
            calls: Arc::clone(&calls),
        }),
        StateStore::new(not_a_directory.join("state.json")),
        DesktopState::default(),
    );
    let mut candidate = DesktopState::default();

    assert!(!enable_launch_at_login_after_pair(&runtime, &mut candidate));
    assert_eq!(*calls.lock().expect("autostart calls"), vec![true, false]);
    assert!(!candidate.launch_at_login);
    let error = candidate.last_error.as_deref().expect("repair error");
    assert!(error.contains("persistence and rollback failures"));
    assert!(error.contains("fixture rollback failed"));
}

#[test]
fn pairing_repair_stops_an_existing_poller_before_lifecycle_release() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let runtime = Runtime::from_loaded_state(
        Box::new(RollbackFailingPlatform {
            credentials: FakeCredentialStore::default(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }),
        StateStore::new(directory.path().join("state.json")),
        DesktopState::default(),
    );
    runtime.polling_enabled.store(true, Ordering::Release);
    let before = runtime.poll_generation.load(Ordering::Acquire);
    let operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .expect("pairing lifecycle reservation");

    super::sync::stop_polling(&runtime);

    assert!(!runtime.polling_enabled.load(Ordering::Acquire));
    assert_eq!(runtime.poll_generation.load(Ordering::Acquire), before + 1);
    assert!(matches!(
        runtime.coordinator.begin_run(),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    drop(operation);
}

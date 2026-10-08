use std::{
    path::Path,
    sync::{atomic::Ordering, Arc, Mutex},
};

use shellx_drive_desktop_core::{
    CredentialStore, DesktopError, DesktopState, FakeCredentialStore, Result as CoreResult,
    StateStore, SyncPair,
};

use super::*;

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
fn marker_rollback_never_deletes_the_selected_base() {
    let directory = tempfile::tempdir().expect("temp directory");
    let base = directory.path().join("Drive");
    std::fs::create_dir(&base).expect("base");
    let base_guard = UnixRootGuard::acquire(&base, None).expect("base guard");
    base_guard
        .ensure_directory(Path::new("My files"))
        .expect("root directory");
    let root = base.join("My files");
    let guard = UnixRootGuard::acquire(&root, None).expect("root guard");
    let pair = SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "My files".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: root.clone(),
        local_root_identity: Some(guard.identity().clone()),
    };
    guard
        .write_or_recognize_pair_marker(&PairMarker::from(&pair))
        .expect("marker");
    rollback_created_markers(&[pair]);
    assert!(base.is_dir());
    assert!(root.is_dir());
    assert!(!root.join(".shellx-drive-pair.json").exists());
}

#[test]
fn pairing_startup_repair_stops_armed_poller_before_lifecycle_release() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let blocked_parent = directory.path().join("state-parent");
    std::fs::write(&blocked_parent, b"regular file blocks state directory")
        .expect("fixture state parent");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let runtime = Runtime::from_loaded_state(
        Box::new(RollbackFailingPlatform {
            credentials: FakeCredentialStore::default(),
            calls: Arc::clone(&calls),
        }),
        StateStore::new(blocked_parent.join("state.json")),
        DesktopState::default(),
    );
    runtime.polling_enabled.store(true, Ordering::Release);
    let generation = runtime.poll_generation.load(Ordering::Acquire);
    let mut operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .expect("pairing lifecycle reservation");
    let mut candidate = DesktopState::default();

    assert!(!enable_launch_at_login_after_pair(&runtime, &mut candidate));

    assert_eq!(*calls.lock().expect("autostart calls"), vec![true, false]);
    assert!(!candidate.launch_at_login);
    assert!(candidate.last_error.is_some());
    assert!(!runtime.polling_enabled.load(Ordering::Acquire));
    assert_eq!(
        runtime.poll_generation.load(Ordering::Acquire),
        generation + 1
    );
    assert!(matches!(
        runtime.coordinator.begin_run(),
        Err(DesktopError::SyncAlreadyRunning)
    ));

    operation.finish_state(candidate);
    assert!(runtime.coordinator.snapshot().last_error.is_some());
}

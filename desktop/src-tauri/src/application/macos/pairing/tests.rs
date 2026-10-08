use std::{
    path::Path,
    sync::{atomic::Ordering, Arc, Mutex},
};

use shellx_drive_desktop_core::{
    CredentialStore, DesktopError, DesktopState, FakeCredentialStore, Result as CoreResult,
    StateStore,
};

use super::Runtime;

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
fn folder_materialization_retains_saved_startup_and_pause_choices() {
    use shellx_drive_desktop_core::{SyncRoot, SyncRootKind, SyncRootRole};
    let root = SyncRoot {
        id: "workspace:one".to_string(),
        kind: SyncRootKind::Workspace,
        workspace_id: "one".to_string(),
        root_file_id: None,
        grant_id: None,
        owner_label: "Owner".to_string(),
        role: SyncRootRole::Owner,
        access_generation: 1,
        expires_at: None,
        label: "Files".to_string(),
    };
    for launch_at_login in [false, true] {
        let directory = tempfile::tempdir().expect("temporary Drive folder");
        // macOS exposes its temporary directory through /var, a symlink to
        // /private/var. Native root guards require the physical parent chain.
        let base = directory
            .path()
            .canonicalize()
            .expect("physical Drive folder");
        let mut candidate = DesktopState {
            launch_at_login,
            paused: true,
            sync_root_base: Some(base.clone()),
            ..DesktopState::default()
        };
        super::pairing::materialize_roots(
            &mut candidate,
            std::slice::from_ref(&root),
            &crate::session_identity::SessionIdentity::new(
                "https://drive.example.test",
                "owner@example.test",
            ),
            "https://drive.example.test",
            &base,
        )
        .unwrap();
        assert_eq!(candidate.launch_at_login, launch_at_login);
        assert!(candidate.paused);
        assert_eq!(candidate.pair_count(), 1);
        assert!(candidate
            .pair
            .as_ref()
            .unwrap()
            .local_root
            .starts_with(&base));
    }
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

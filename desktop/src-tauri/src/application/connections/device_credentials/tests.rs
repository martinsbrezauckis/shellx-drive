use std::{
    cell::RefCell,
    path::Path,
    sync::{Arc, Mutex},
};

use shellx_drive_desktop_core::{
    desktop_agent_enrollment_fingerprint, desktop_agent_pair_fingerprint, CredentialStore,
    DesktopAgentCommandKind, DesktopState, DisconnectCleanupIntent, DisconnectCredentialSlot,
    FakeCredentialStore, Result as CoreResult, StateStore, SyncPair,
};

use super::*;
use crate::{
    application::{
        desktop_agent::{device_credential, scoped_device_cleanup_slot},
        Runtime,
    },
    platform::PlatformServices,
};

#[derive(Default)]
struct MemoryStore {
    values: FakeCredentialStore,
    operations: Mutex<Vec<String>>,
}

impl CredentialStore for MemoryStore {
    fn get(&self, key: &str) -> CoreResult<Option<String>> {
        self.operations.lock().unwrap().push(format!("get:{key}"));
        self.values.get(key)
    }
    fn set(&self, key: &str, credential: &str) -> CoreResult<()> {
        self.operations.lock().unwrap().push(format!("set:{key}"));
        self.values.set(key, credential)
    }
    fn delete(&self, key: &str) -> CoreResult<()> {
        self.operations
            .lock()
            .unwrap()
            .push(format!("delete:{key}"));
        self.values.delete(key)
    }
}

thread_local! { static STORE: RefCell<Arc<MemoryStore>> = RefCell::new(Arc::new(MemoryStore::default())); }
struct MemoryPlatform(Arc<MemoryStore>);
impl PlatformServices for MemoryPlatform {
    fn credentials(&self) -> &dyn CredentialStore {
        self.0.as_ref()
    }
    fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
        self.0.as_ref()
    }
    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
        self.0.as_ref()
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

fn factory(store: StateStore, state: DesktopState) -> CoreResult<Runtime> {
    Ok(Runtime::from_loaded_state(
        Box::new(MemoryPlatform(
            STORE.with(|store| Arc::clone(&store.borrow())),
        )),
        store,
        state,
    ))
}

struct Harness {
    // Drop all pinned manager handles before the temporary directory.
    manager: ConnectionManager,
    credentials: Arc<MemoryStore>,
    directory: tempfile::TempDir,
}

impl Harness {
    fn legacy() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let credentials = Arc::new(MemoryStore::default());
        STORE.with(|store| *store.borrow_mut() = Arc::clone(&credentials));
        let state = old_state(
            &directory.path().join("legacy-root"),
            "https://first.example.test",
            "first@example.test",
        );
        let store = StateStore::new(directory.path().join("state.json"));
        store.save(&state).unwrap();
        let primary = Arc::new(factory(store, state).unwrap());
        let manager =
            ConnectionManager::load_without_credential_migration(primary, factory).unwrap();
        credentials
            .set("device_shared", "sxd_device_original")
            .unwrap();
        Self {
            manager,
            credentials,
            directory,
        }
    }

    fn add_legacy(&self) -> String {
        let id = self.manager.begin_connection("Other".into()).unwrap();
        self.manager
            .reserve_identity(&id, "https://second.example.test", "second@example.test")
            .unwrap();
        let runtime = self.manager.resolve(Some(&id)).unwrap();
        self.credentials
            .values
            .set(
                &Runtime::credential_key("https://second.example.test", "second@example.test"),
                "fixture_owner_session",
            )
            .unwrap();
        let state = old_state(
            &self.directory.path().join("second-root"),
            "https://second.example.test",
            "second@example.test",
        );
        runtime.store.save(&state).unwrap();
        runtime
            .coordinator
            .begin_lifecycle_operation()
            .unwrap()
            .finish_state(state);
        self.manager.complete_connection(&id).unwrap();
        id
    }

    fn restart(&self) -> ConnectionManager {
        let store = StateStore::new(self.directory.path().join("state.json"));
        let state = store.load().unwrap();
        ConnectionManager::load(Arc::new(factory(store, state).unwrap()), factory).unwrap()
    }
}

fn old_state(root: &Path, server: &str, email: &str) -> DesktopState {
    let mut state = DesktopState::default();
    state
        .configure_pair(SyncPair {
            server_url: server.to_string(),
            account_email: email.to_string(),
            workspace_id: "workspace".into(),
            workspace_name: "Fixture".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: root.to_path_buf(),
            local_root_identity: None,
        })
        .unwrap();
    state
        .desktop_agent_control
        .enroll(
            "device_shared".into(),
            None,
            desktop_agent_enrollment_fingerprint(server, email),
        )
        .unwrap();
    state.desktop_agent_control.credential_key = None;
    state
}

mod destination;
mod identity;
mod lifecycle;
mod ownership;

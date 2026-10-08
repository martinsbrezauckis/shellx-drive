use std::{path::Path, sync::Arc};

use shellx_drive_desktop_core::{
    CredentialStore, DesktopState, FakeCredentialStore, Result as CoreResult, StateStore, SyncPair,
};

use super::*;

mod lifecycle;
mod persistence;
mod view;

struct TestPlatform(FakeCredentialStore);

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

fn factory(store: StateStore, state: DesktopState) -> CoreResult<Runtime> {
    let credentials = FakeCredentialStore::default();
    if let Some(identity) = migration::state_identity(&state)? {
        credentials.set(
            &identity.session().credential_key(),
            "synthetic-test-session",
        )?;
    }
    Ok(Runtime::from_loaded_state(
        Box::new(TestPlatform(credentials)),
        store,
        state,
    ))
}

struct Harness {
    manager: ConnectionManager,
    // Close the manager's pinned Windows handles before TempDir cleanup.
    directory: tempfile::TempDir,
}

impl Harness {
    fn fresh() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let primary = Arc::new(
            factory(
                StateStore::new(directory.path().join("state.json")),
                DesktopState::default(),
            )
            .unwrap(),
        );
        let manager = ConnectionManager::load(primary, factory).unwrap();
        Self { directory, manager }
    }

    fn preferences(&self) {
        self.manager
            .save_preferences("system".to_string(), false, 20)
            .unwrap();
    }

    fn add(&self, name: &str, email: &str) -> String {
        let id = self.manager.begin_connection(name.to_string()).unwrap();
        self.manager
            .reserve_identity(&id, "https://drive.example.test", email)
            .unwrap();
        id
    }

    fn pair(&self, id: &str, email: &str, leaf: &str) -> std::path::PathBuf {
        let root = self.stage_pair(id, email, leaf);
        self.manager.complete_connection(id).unwrap();
        root
    }

    fn stage_pair(&self, id: &str, email: &str, leaf: &str) -> std::path::PathBuf {
        let runtime = self.manager.resolve(Some(id)).unwrap();
        let root = self.directory.path().join(leaf);
        std::fs::create_dir(&root).unwrap();
        runtime
            .platform
            .credentials()
            .set(
                &SessionIdentity::credential_key_for("https://drive.example.test", email),
                "synthetic-test-session",
            )
            .unwrap();
        runtime
            .coordinator
            .configure_pair(pair(root.clone(), email))
            .unwrap();
        runtime.save().unwrap();
        root
    }

    fn restart(&self) -> ConnectionManager {
        let store = StateStore::new(self.directory.path().join("state.json"));
        let state = store.load().unwrap();
        ConnectionManager::load(Arc::new(factory(store, state).unwrap()), factory).unwrap()
    }
}

fn pair(root: std::path::PathBuf, email: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: email.to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Shared root".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: root,
        local_root_identity: None,
    }
}

#[test]
fn preferences_precede_setup_and_account_admission_uses_verified_identity() {
    let harness = Harness::fresh();
    assert!(!harness.manager.preferences().initialized);
    assert!(harness
        .manager
        .begin_connection("Work".to_string())
        .is_err());
    harness.preferences();
    let work = harness.add("Work", "Work@Example.test");
    let personal = harness.add("Personal", "personal@example.test");
    assert!(
        harness.manager.view().connections.is_empty(),
        "unpaired drafts are hidden during this session"
    );
    assert!(harness.manager.identity_for(&work).unwrap().email == "work@example.test");
    assert_ne!(work, personal);
    let duplicate = harness
        .manager
        .begin_connection("Duplicate".to_string())
        .unwrap();
    let error = harness
        .manager
        .reserve_identity(
            &duplicate,
            "https://DRIVE.example.test/",
            "work@example.test",
        )
        .unwrap_err();
    assert!(error.to_string().contains(&work));
    assert!(harness.manager.identity_for(&duplicate).is_none());
    assert!(harness
        .manager
        .reserve_identity(&work, "https://drive.example.test", "another@example.test")
        .is_err());
}

#[test]
fn concurrent_duplicate_admission_has_one_owner() {
    let harness = Harness::fresh();
    harness.preferences();
    let first = harness
        .manager
        .begin_connection("First".to_string())
        .unwrap();
    let second = harness
        .manager
        .begin_connection("Second".to_string())
        .unwrap();
    let outcomes = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            harness.manager.reserve_identity(
                &first,
                "https://drive.example.test",
                "same@example.test",
            )
        });
        let right = scope.spawn(|| {
            harness.manager.reserve_identity(
                &second,
                "https://drive.example.test",
                "same@example.test",
            )
        });
        [left.join().unwrap().is_ok(), right.join().unwrap().is_ok()]
    });
    assert_eq!(outcomes.into_iter().filter(|admitted| *admitted).count(), 1);
}

#[test]
fn intervals_inherit_without_rebinding_roots_and_cancel_guard_is_exact() {
    let harness = Harness::fresh();
    harness.preferences();
    let work = harness.add("Work", "work@example.test");
    let personal = harness.add("Personal", "personal@example.test");
    assert!(harness.manager.is_preparing(&work));
    let work_root = harness.pair(&work, "work@example.test", "work");
    harness.pair(&personal, "personal@example.test", "personal");
    assert!(!harness.manager.is_preparing(&work));
    harness
        .manager
        .save_connection(&work, "Renamed work".to_string(), Some(300))
        .unwrap();
    harness
        .manager
        .save_preferences("dark".to_string(), false, 60)
        .unwrap();
    let work_runtime = harness.manager.resolve(Some(&work)).unwrap();
    let personal_runtime = harness.manager.resolve(Some(&personal)).unwrap();
    assert_eq!(
        harness.manager.effective_interval(&work_runtime),
        Duration::from_secs(300)
    );
    assert_eq!(
        harness.manager.effective_interval(&personal_runtime),
        Duration::from_secs(60)
    );
    assert_eq!(
        work_runtime.coordinator.snapshot().pair.unwrap().local_root,
        work_root
    );
    harness
        .manager
        .save_connection(&work, "Renamed work".to_string(), None)
        .unwrap();
    assert_eq!(
        harness.manager.effective_interval(&work_runtime),
        Duration::from_secs(60)
    );
    let view = harness.manager.view();
    assert!(
        view.connections
            .iter()
            .all(|connection| connection.connection_folder.is_none()),
        "legacy-style single roots have no invented container"
    );
}

#[test]
fn removal_keeps_folder_ownership_until_memory_and_disk_are_terminal() {
    let harness = Harness::fresh();
    harness.preferences();
    let id = harness.add("Work", "work@example.test");
    let root = harness.pair(&id, "work@example.test", "work");
    assert!(harness.manager.finish_removal(&id).is_err());
    harness.manager.mark_removing(&id).unwrap();
    assert!(harness.manager.finish_removal(&id).is_err());
    let runtime = harness.manager.resolve(Some(&id)).unwrap();
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    operation
        .publish_persisted_state(DesktopState::default())
        .unwrap();
    operation.finish_state(DesktopState::default());
    assert!(
        harness.manager.finish_removal(&id).is_err(),
        "disk still retains the pair"
    );
    assert!(harness
        .manager
        .folder_reservations()
        .iter()
        .any(|folder| folder.path == root));
    runtime.save().unwrap();
    harness.manager.finish_removal(&id).unwrap();
    assert!(harness.manager.resolve(Some(&id)).is_err());
    assert!(harness.manager.folder_reservations().is_empty());
    let restarted = harness.restart();
    assert!(
        restarted.view().connections.is_empty(),
        "retired state is not rediscovered as orphan setup"
    );
    assert!(
        root.is_dir(),
        "removal never deletes local files or the folder"
    );
}

#[test]
fn completion_and_form_cancellation_have_exactly_one_winner() {
    let harness = Harness::fresh();
    harness.preferences();
    let id = harness.add("Work", "work@example.test");
    harness.stage_pair(&id, "work@example.test", "work");
    let outcomes = std::thread::scope(|scope| {
        let complete = scope.spawn(|| harness.manager.complete_connection(&id));
        let cancel = scope.spawn(|| harness.manager.mark_removing_if_preparing(&id));
        [
            complete.join().unwrap().is_ok(),
            cancel.join().unwrap().is_ok(),
        ]
    });
    assert_eq!(outcomes.into_iter().filter(|won| *won).count(), 1);
    let lifecycle = harness.manager.view().connections[0].lifecycle;
    assert_eq!(
        lifecycle,
        if outcomes[0] {
            ConnectionLifecycle::Active
        } else {
            ConnectionLifecycle::Removing
        }
    );
    assert_eq!(
        harness.manager.mark_removing_if_preparing(&id).is_ok(),
        !outcomes[0],
        "only the cancellation winner may retry cleanup"
    );
}

#[test]
fn global_update_guard_blocks_catalog_mutation_and_releases_on_drop() {
    let harness = Harness::fresh();
    harness.preferences();
    let id = harness.add("Work", "work@example.test");
    let guard = harness.manager.begin_global_update().unwrap();
    assert!(harness.manager.begin_global_update().is_err());
    assert!(harness.manager.begin_connection("New".to_string()).is_err());
    assert!(harness
        .manager
        .save_connection(&id, "Changed".to_string(), None)
        .is_err());
    assert!(harness
        .manager
        .save_preferences("light".to_string(), true, 60)
        .is_err());
    assert!(harness
        .manager
        .reserve_identity(&id, "https://drive.example.test", "work@example.test")
        .is_err());
    assert!(
        harness.manager.resolve(Some(&id)).is_ok(),
        "read-only routing remains available"
    );
    drop(guard);
    assert!(harness.manager.begin_connection("New".to_string()).is_ok());
}

#[test]
fn missing_other_disk_allows_existing_sync_but_blocks_new_folder_admission() {
    let harness = Harness::fresh();
    harness.preferences();
    let healthy = harness.add("Healthy", "healthy@example.test");
    let missing = harness.add("Missing disk", "missing@example.test");
    let healthy_root = harness.pair(&healthy, "healthy@example.test", "healthy");
    let missing_root = harness.pair(&missing, "missing@example.test", "missing");
    std::fs::remove_dir(&missing_root).unwrap();
    harness
        .manager
        .validate_existing_connection_folder(&healthy, &healthy_root)
        .unwrap();
    let next = harness.add("New", "next@example.test");
    let next_root = harness.directory.path().join("next");
    std::fs::create_dir(&next_root).unwrap();
    assert!(harness
        .manager
        .validate_local_folder(&next, &next_root)
        .is_err());
}

#[test]
fn queued_sync_permit_rechecks_global_update_and_does_not_leak_capacity() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    let harness = Harness::fresh();
    harness.preferences();
    let id = harness.add("Work", "work@example.test");
    harness.pair(&id, "work@example.test", "work");
    let runtime = harness.manager.resolve(Some(&id)).unwrap();
    let first = Arc::clone(&harness.manager.sync_permits)
        .try_acquire_owned()
        .unwrap();
    let second = Arc::clone(&harness.manager.sync_permits)
        .try_acquire_owned()
        .unwrap();
    let mut waiting = Box::pin(harness.manager.acquire_sync_permit_for(&runtime));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Pending));
    let update = harness.manager.begin_global_update().unwrap();
    drop(first);
    assert!(matches!(
        waiting.as_mut().poll(&mut context),
        Poll::Ready(Err(_))
    ));
    drop(waiting);
    drop(update);
    drop(second);
    assert_eq!(harness.manager.sync_permits.available_permits(), 2);
}

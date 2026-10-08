use super::*;

use shellx_drive_desktop_core::{ActivityEntry, DisconnectCleanupIntent, RemoteSessionRecord};

struct SharedTestPlatform(Arc<FakeCredentialStore>);

impl crate::platform::PlatformServices for SharedTestPlatform {
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

fn shared_factory(store: StateStore, state: DesktopState) -> CoreResult<Runtime> {
    static CREDENTIALS: std::sync::OnceLock<Arc<FakeCredentialStore>> = std::sync::OnceLock::new();
    let credentials = Arc::clone(CREDENTIALS.get_or_init(Default::default));
    if let Some(identity) = migration::state_identity(&state)? {
        let key = identity.session().credential_key();
        if credentials.get(&key)?.is_none() {
            credentials.set(&key, "synthetic-old-session")?;
        }
    }
    Ok(Runtime::from_loaded_state(
        Box::new(SharedTestPlatform(credentials)),
        store,
        state,
    ))
}

fn publish(runtime: &Runtime, state: DesktopState) {
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    runtime.store.save(&state).unwrap();
    operation.finish_state(state);
}

fn interrupted_pair() -> (Harness, String, ConnectionManager) {
    let harness = Harness::fresh();
    harness.preferences();
    let id = harness.add("Interrupted", "work@example.test");
    harness.stage_pair(&id, "work@example.test", "paired-root");
    let restarted = harness.restart();
    assert_eq!(
        restarted.view().connections[0].lifecycle,
        ConnectionLifecycle::Recovery
    );
    (harness, id, restarted)
}

#[test]
fn retired_legacy_default_cannot_reach_a_readded_accounts_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let email = format!("legacy-{}@example.test", uuid::Uuid::new_v4());
    let root = directory.path().join("legacy-root");
    std::fs::create_dir(&root).unwrap();
    let state = DesktopState {
        pair: Some(pair(root, &email)),
        ..DesktopState::default()
    };
    let store = StateStore::new(directory.path().join("state.json"));
    store.save(&state).unwrap();
    let primary = Arc::new(shared_factory(store, state).unwrap());
    let manager = ConnectionManager::load(Arc::clone(&primary), shared_factory).unwrap();
    assert!(Arc::ptr_eq(&manager.resolve(None).unwrap(), &primary));
    let harness = Harness { manager, directory };
    harness.manager.mark_removing(LEGACY_CONNECTION_ID).unwrap();
    let key = SessionIdentity::credential_key_for("https://drive.example.test", &email);
    primary.platform.credentials().delete(&key).unwrap();
    publish(&primary, DesktopState::default());
    harness
        .manager
        .finish_removal(LEGACY_CONNECTION_ID)
        .unwrap();

    let replacement = harness.add("Replacement", &email);
    harness.pair(&replacement, &email, "replacement-root");
    let replacement_runtime = harness.manager.resolve(Some(&replacement)).unwrap();
    replacement_runtime
        .platform
        .credentials()
        .set(&key, "synthetic-replacement-session")
        .unwrap();
    assert!(
        primary.owns_credential_key(&key),
        "the retained app owner has stale identity metadata"
    );
    assert!(harness.manager.resolve(None).is_err());
    assert!(harness.manager.resolve(Some(LEGACY_CONNECTION_ID)).is_err());
    assert_eq!(
        replacement_runtime
            .platform
            .credentials()
            .get(&key)
            .unwrap()
            .as_deref(),
        Some("synthetic-replacement-session")
    );
    assert!(Arc::ptr_eq(
        &harness.manager.app_service_runtime(),
        &primary
    ));
    assert!(!Arc::ptr_eq(&replacement_runtime, &primary));
    let restarted = harness.restart();
    assert!(restarted.resolve(None).is_err());
    assert!(restarted.resolve(Some(LEGACY_CONNECTION_ID)).is_err());
    assert!(restarted.resolve(Some(&replacement)).is_ok());
}

#[test]
fn explicit_completion_resumes_crash_after_pair_without_rewriting_saved_state() {
    let harness = Harness::fresh();
    harness.preferences();
    let id = harness.add("Interrupted", "work@example.test");
    let root = harness.stage_pair(&id, "work@example.test", "paired-root");
    let runtime = harness.manager.resolve(Some(&id)).unwrap();
    let mut state = runtime.coordinator.snapshot();
    state.paused = true;
    state.change_cursor = 77;
    state.append_activity(ActivityEntry {
        at: chrono::Utc::now(),
        direction: "download".to_string(),
        relative_path: "report.txt".into(),
        result: "completed".to_string(),
    });
    state
        .desktop_agent_control
        .enroll(
            "existing-device".to_string(),
            Some(chrono::Utc::now() + chrono::Duration::days(7)),
            shellx_drive_desktop_core::desktop_agent_enrollment_fingerprint(
                "https://drive.example.test",
                "work@example.test",
            ),
        )
        .unwrap();
    publish(&runtime, state.clone());
    let retained_root = harness.directory.path().join("retained-old-root");
    std::fs::create_dir(&retained_root).unwrap();
    harness
        .manager
        .retain_folder_reservation(&id, retained_root.clone(), None)
        .unwrap();
    let bytes = std::fs::read(runtime.store.path()).unwrap();
    let restarted = harness.restart();
    let recovered = restarted.resolve(Some(&id)).unwrap();
    assert!(!restarted.may_sync(&recovered));
    let view = restarted.complete_connection(&id).unwrap();
    assert_eq!(view.connections[0].lifecycle, ConnectionLifecycle::Active);
    assert!(view.connections[0].view.error.is_none());
    assert!(restarted.may_sync(&recovered));
    assert_eq!(recovered.coordinator.snapshot(), state);
    assert_eq!(std::fs::read(recovered.store.path()).unwrap(), bytes);
    let folders = restarted.folder_reservations();
    assert!(folders.iter().any(|folder| folder.path == root));
    assert!(folders.iter().any(|folder| folder.path == retained_root));
    assert_eq!(restarted.preferences(), harness.manager.preferences());
}

#[test]
fn recovery_completion_rejects_unpaired_busy_and_removing_connections() {
    let harness = Harness::fresh();
    harness.preferences();
    let unpaired = harness.add("Unpaired", "unpaired@example.test");
    let restarted = harness.restart();
    assert!(restarted.complete_connection(&unpaired).is_err());
    assert_eq!(
        restarted.view().connections[0].lifecycle,
        ConnectionLifecycle::Recovery
    );

    let (_harness, id, restarted) = interrupted_pair();
    let runtime = restarted.resolve(Some(&id)).unwrap();
    let operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    assert!(restarted.complete_connection(&id).is_err());
    drop(operation);
    restarted.mark_removing(&id).unwrap();
    assert!(restarted.complete_connection(&id).is_err());
    assert_eq!(
        restarted.view().connections[0].lifecycle,
        ConnectionLifecycle::Removing
    );
}

#[test]
fn recovery_completion_rejects_missing_credentials_and_pending_session_cleanup() {
    for pending in [false, true] {
        let (_harness, id, restarted) = interrupted_pair();
        let runtime = restarted.resolve(Some(&id)).unwrap();
        if pending {
            let mut state = runtime.coordinator.snapshot();
            state.pending_candidate_session = Some(
                RemoteSessionRecord::new(
                    "https://drive.example.test",
                    "work@example.test",
                    "pending-exact-session",
                    chrono::Utc::now() + chrono::Duration::hours(1),
                )
                .unwrap(),
            );
            publish(&runtime, state);
        } else {
            runtime
                .platform
                .credentials()
                .delete(&SessionIdentity::credential_key_for(
                    "https://drive.example.test",
                    "work@example.test",
                ))
                .unwrap();
        }
        assert!(restarted.complete_connection(&id).is_err());
        assert_eq!(
            restarted.view().connections[0].lifecycle,
            ConnectionLifecycle::Recovery
        );
        assert!(!restarted.folder_reservations().is_empty());
    }
    let (_harness, id, restarted) = interrupted_pair();
    let runtime = restarted.resolve(Some(&id)).unwrap();
    let mut state = runtime.coordinator.snapshot();
    state
        .begin_disconnect_cleanup(
            DisconnectCleanupIntent::for_disconnect_pairs(
                state.pairs().cloned().collect(),
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    publish(&runtime, state);
    assert!(restarted.complete_connection(&id).is_err());
    assert_eq!(
        restarted.view().connections[0].lifecycle,
        ConnectionLifecycle::Recovery
    );
}

#[test]
fn recovery_completion_rejects_missing_corrupt_and_changed_durable_state() {
    for image in [
        None,
        Some(b"corrupt".as_slice()),
        Some(b"changed".as_slice()),
    ] {
        let (_harness, id, restarted) = interrupted_pair();
        let runtime = restarted.resolve(Some(&id)).unwrap();
        match image {
            None => std::fs::remove_file(runtime.store.path()).unwrap(),
            Some(b"changed") => {
                let mut changed = runtime.coordinator.snapshot();
                changed.change_cursor += 1;
                runtime.store.save(&changed).unwrap();
            }
            Some(bytes) => std::fs::write(runtime.store.path(), bytes).unwrap(),
        }
        let before = std::fs::read(runtime.store.path()).ok();
        assert!(restarted.complete_connection(&id).is_err());
        assert_eq!(std::fs::read(runtime.store.path()).ok(), before);
        assert_eq!(
            restarted.view().connections[0].lifecycle,
            ConnectionLifecycle::Recovery
        );
        assert!(!restarted.folder_reservations().is_empty());
    }
}

#[test]
fn recovery_completion_rejects_account_mismatch_and_unavailable_runtime() {
    let (harness, id, restarted) = interrupted_pair();
    let runtime = restarted.resolve(Some(&id)).unwrap();
    let mut changed = runtime.coordinator.snapshot();
    changed.pair.as_mut().unwrap().account_email = "other@example.test".to_string();
    runtime
        .platform
        .credentials()
        .set(
            &SessionIdentity::credential_key_for(
                "https://drive.example.test",
                "other@example.test",
            ),
            "synthetic-other-session",
        )
        .unwrap();
    publish(&runtime, changed);
    assert!(restarted.complete_connection(&id).is_err());
    assert_eq!(
        restarted.identity_for(&id).unwrap().email,
        "work@example.test"
    );
    assert!(!restarted.folder_reservations().is_empty());
    let blocked = harness.restart();
    assert!(blocked.resolve(Some(&id)).is_err());
    assert!(blocked.complete_connection(&id).is_err());
    assert!(blocked.has_unavailable_connections());
    assert_eq!(
        blocked.view().connections[0].lifecycle,
        ConnectionLifecycle::Recovery
    );
    assert!(!blocked.folder_reservations().is_empty());
}

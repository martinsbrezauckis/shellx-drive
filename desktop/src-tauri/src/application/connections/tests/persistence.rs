use super::*;

#[cfg(target_os = "windows")]
#[test]
fn long_state_directory_preserves_atomic_catalog_replacement() {
    use std::os::windows::ffi::OsStrExt;

    let directory = tempfile::tempdir().unwrap();
    let mut parent = directory.path().to_path_buf();
    while parent.as_os_str().encode_wide().count() < 300 {
        parent.push("legal-nested-state-directory");
    }
    std::fs::create_dir_all(&parent).unwrap();
    let runtime = Arc::new(
        factory(
            StateStore::new(parent.join("state.json")),
            DesktopState::default(),
        )
        .unwrap(),
    );
    let manager = ConnectionManager::load(runtime, factory).unwrap();
    manager
        .save_preferences("system".to_string(), false, 20)
        .unwrap();
    let catalog_path = parent.join(".shellx-drive-private/connections-v1/catalog.json");
    let first = std::fs::read(&catalog_path).unwrap();
    manager
        .save_preferences("dark".to_string(), false, 60)
        .unwrap();
    assert_ne!(std::fs::read(&catalog_path).unwrap(), first);
    assert_eq!(
        manager.store.load().unwrap(),
        Some(manager.catalog.lock().unwrap().clone())
    );
}

#[test]
fn failed_draft_cancellation_can_retry_persisted_removal_without_admitting_saved_connections() {
    let harness = Harness::fresh();
    harness.preferences();
    let draft = harness.add("Draft", "draft@example.test");
    let draft_root = harness.stage_pair(&draft, "draft@example.test", "draft");
    let active = harness.add("Active", "active@example.test");
    harness.pair(&active, "active@example.test", "active");
    let interrupted = harness.add("Interrupted", "interrupted@example.test");

    harness.manager.mark_removing_if_preparing(&draft).unwrap();
    let persisted = harness.manager.store.load().unwrap().unwrap();
    assert_eq!(
        persisted
            .connections
            .iter()
            .find(|profile| profile.id == draft)
            .unwrap()
            .lifecycle,
        ConnectionLifecycle::Removing
    );
    // Model native cleanup returning an error: its pair and folder remain,
    // while the catalog's removal intent is already durable.
    harness.manager.mark_removing_if_preparing(&draft).unwrap();
    assert_eq!(harness.manager.store.load().unwrap(), Some(persisted));
    assert!(harness.manager.complete_connection(&draft).is_err());
    assert!(harness.manager.mark_removing_if_preparing(&active).is_err());
    assert!(harness
        .manager
        .folder_reservations()
        .iter()
        .any(|folder| folder.path == draft_root));

    let restarted = harness.restart();
    restarted.mark_removing_if_preparing(&draft).unwrap();
    assert!(restarted.mark_removing_if_preparing(&active).is_err());
    assert!(restarted.mark_removing_if_preparing(&interrupted).is_err());
    let view = restarted.view();
    assert_eq!(
        view.connections
            .iter()
            .find(|connection| connection.id == draft)
            .unwrap()
            .lifecycle,
        ConnectionLifecycle::Removing
    );
    assert_eq!(
        view.connections
            .iter()
            .find(|connection| connection.id == active)
            .unwrap()
            .lifecycle,
        ConnectionLifecycle::Active
    );
    assert_eq!(
        view.connections
            .iter()
            .find(|connection| connection.id == interrupted)
            .unwrap()
            .lifecycle,
        ConnectionLifecycle::Recovery
    );
}

#[test]
fn catalog_replacement_keeps_an_open_previous_image_and_reopens_private_files() {
    #[cfg(unix)]
    use std::io::Read;

    let harness = Harness::fresh();
    harness.preferences();
    let id = harness.add("Work", "work@example.test");
    let root = harness.pair(&id, "work@example.test", "work");
    assert!(harness
        .manager
        .folder_reservations()
        .iter()
        .any(|folder| folder.path == root));
    let catalog_path = harness
        .directory
        .path()
        .join(".shellx-drive-private/connections-v1/catalog.json");
    let previous_bytes = std::fs::read(&catalog_path).unwrap();
    #[cfg(unix)]
    let mut previous_image = std::fs::File::open(&catalog_path).unwrap();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        // A Windows reader may prevent native replacement. Make that boundary
        // deterministic by withholding delete sharing, rather than requiring
        // Unix semantics for a handle retained outside the catalog transaction.
        let previous_image = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&catalog_path)
            .unwrap();
        let previous_catalog = harness.manager.catalog.lock().unwrap().clone();
        let error = harness
            .manager
            .save_preferences("dark".to_string(), true, 60)
            .err()
            .expect("the held reader blocks native replacement");
        assert!(
            matches!(error, shellx_drive_desktop_core::DesktopError::Io(ref error)
            if matches!(error.raw_os_error(), Some(5 | 32)))
        );
        assert_eq!(std::fs::read(&catalog_path).unwrap(), previous_bytes);
        assert_eq!(
            *harness.manager.catalog.lock().unwrap(),
            previous_catalog,
            "failed replacement preserves preferences and folder reservations"
        );
        assert!(std::fs::read_dir(catalog_path.parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".catalog-")));
        drop(previous_image);
    }

    harness
        .manager
        .save_preferences("dark".to_string(), true, 60)
        .unwrap();
    harness
        .manager
        .save_preferences("light".to_string(), false, 300)
        .unwrap();

    #[cfg(unix)]
    {
        let mut retained_bytes = Vec::new();
        previous_image.read_to_end(&mut retained_bytes).unwrap();
        assert_eq!(
            retained_bytes, previous_bytes,
            "catalog save replaces its image atomically"
        );
    }
    assert_ne!(std::fs::read(&catalog_path).unwrap(), previous_bytes);
    let restarted = harness.restart();
    assert_eq!(restarted.preferences().theme, "light");
    assert_eq!(restarted.preferences().default_sync_interval_seconds, 300);
    assert!(!restarted.preferences().launch_at_login);
    assert!(std::fs::read_dir(catalog_path.parent().unwrap())
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".catalog-")));
}

#[test]
fn legacy_migration_preserves_exact_state_bytes_and_root_identity() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("legacy-root");
    std::fs::create_dir(&root).unwrap();
    let mut legacy_pair = pair(root.clone(), "work@example.test");
    legacy_pair.local_root_identity = Some(DirectoryIdentity::unix(17, 42));
    let mut state = DesktopState {
        pair: Some(legacy_pair),
        paused: true,
        launch_at_login: false,
        change_cursor: 77,
        ..DesktopState::default()
    };
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
    state
        .desktop_agent_control
        .record_lease(
            "existing-command".to_string(),
            "existing-lease".to_string(),
            shellx_drive_desktop_core::DesktopAgentCommandKind::SyncNow,
            chrono::Utc::now(),
        )
        .unwrap();
    let bytes = format!("{}\n\n", serde_json::to_string_pretty(&state).unwrap()).into_bytes();
    let path = directory.path().join("state.json");
    std::fs::write(&path, &bytes).unwrap();
    let primary = Arc::new(factory(StateStore::new(&path), state.clone()).unwrap());
    let manager = ConnectionManager::load(Arc::clone(&primary), factory).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(primary.coordinator.snapshot(), state);
    assert!(Arc::ptr_eq(
        &manager.resolve(Some(LEGACY_CONNECTION_ID)).unwrap(),
        &primary
    ));
    assert!(!manager.preferences().launch_at_login);
    assert!(manager.preferences().initialized);
    assert!(manager
        .folder_reservations()
        .iter()
        .any(|folder| folder.path == root));
    assert!(
        !directory
            .path()
            .join("legacy-root")
            .join(".shellx-drive-pair.json")
            .exists(),
        "catalog migration does not create or rewrite markers"
    );
}

#[test]
fn interrupted_preparing_setup_becomes_visible_recovery_without_reauthentication() {
    let harness = Harness::fresh();
    harness.preferences();
    let id = harness.add("Work", "work@example.test");
    assert!(harness.manager.view().connections.is_empty());
    let restarted = harness.restart();
    let view = restarted.view();
    assert_eq!(view.connections.len(), 1);
    assert_eq!(view.connections[0].id, id);
    assert_eq!(view.connections[0].lifecycle, ConnectionLifecycle::Recovery);
    assert_eq!(view.connections[0].view.account, "work@example.test");
    assert!(!restarted.is_preparing(&id));
    assert!(!restarted.may_sync(&restarted.resolve(Some(&id)).unwrap()));
}

#[test]
fn rejected_duplicate_pending_session_keeps_exact_cleanup_without_claiming_the_account() {
    let harness = Harness::fresh();
    harness.preferences();
    let owner = harness.add("Owner", "work@example.test");
    harness.pair(&owner, "work@example.test", "owner");
    let rejected = harness
        .manager
        .begin_connection("Rejected duplicate".to_string())
        .unwrap();
    assert!(harness
        .manager
        .reserve_identity(&rejected, "https://drive.example.test", "work@example.test")
        .is_err());
    let runtime = harness.manager.resolve(Some(&rejected)).unwrap();
    let mut state = runtime.coordinator.snapshot();
    state.pending_candidate_session = Some(
        shellx_drive_desktop_core::RemoteSessionRecord::new(
            "https://drive.example.test",
            "work@example.test",
            "rejected-exact-session",
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .unwrap(),
    );
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    runtime.store.save(&state).unwrap();
    operation.finish_state(state);
    let restarted = harness.restart();
    assert!(
        restarted.identity_for(&rejected).is_none(),
        "a pending-only session is not account admission"
    );
    assert!(
        !restarted
            .resolve(Some(&rejected))
            .unwrap()
            .owns_session_identity(&SessionIdentity::new(
                "https://drive.example.test",
                "work@example.test",
            )),
        "exact pending cleanup does not grant canonical credential ownership"
    );
    assert_eq!(
        restarted
            .resolve(Some(&rejected))
            .unwrap()
            .coordinator
            .snapshot()
            .pending_candidate_session
            .unwrap()
            .session_id,
        "rejected-exact-session"
    );
    restarted
        .reserve_identity(&owner, "https://drive.example.test", "work@example.test")
        .unwrap();
    assert_eq!(
        restarted.identity_for(&owner).unwrap().email,
        "work@example.test"
    );
}

#[test]
fn missing_referenced_state_is_not_defaulted_or_recreated_and_retains_ownership() {
    let harness = Harness::fresh();
    harness.preferences();
    let id = harness.add("Work", "work@example.test");
    let root = harness.pair(&id, "work@example.test", "work");
    let state_path = harness
        .manager
        .resolve(Some(&id))
        .unwrap()
        .store
        .path()
        .to_path_buf();
    std::fs::remove_file(&state_path).unwrap();
    let restarted = harness.restart();
    assert!(restarted.has_unavailable_connections());
    assert!(restarted.resolve(Some(&id)).is_err());
    assert!(
        !state_path.exists(),
        "projection cannot recreate a missing owned state file"
    );
    assert!(restarted
        .folder_reservations()
        .iter()
        .any(|folder| folder.path == root));
    let recovery = restarted
        .view()
        .connections
        .into_iter()
        .find(|connection| connection.id == id)
        .unwrap();
    assert_eq!(recovery.lifecycle, ConnectionLifecycle::Recovery);
    assert_eq!(recovery.view.account, "work@example.test");
    assert!(recovery.view.error.unwrap().contains("missing"));
    let other = restarted.begin_connection("Other".to_string()).unwrap();
    assert!(restarted
        .reserve_identity(&other, "https://drive.example.test", "work@example.test")
        .is_err());
}

#[test]
fn global_preferences_remain_editable_without_overwriting_corrupt_legacy_state() {
    let directory = tempfile::tempdir().unwrap();
    let legacy_root = directory.path().join("legacy");
    std::fs::create_dir(&legacy_root).unwrap();
    let legacy_store = StateStore::new(directory.path().join("state.json"));
    let legacy_state = DesktopState {
        pair: Some(pair(legacy_root, "legacy@example.test")),
        ..DesktopState::default()
    };
    legacy_store.save(&legacy_state).unwrap();
    let manager = ConnectionManager::load(
        Arc::new(factory(legacy_store, legacy_state).unwrap()),
        factory,
    )
    .unwrap();
    let harness = Harness { directory, manager };
    let healthy = harness.add("Healthy", "healthy@example.test");
    harness.pair(&healthy, "healthy@example.test", "healthy");
    let legacy_path = harness.directory.path().join("state.json");
    let retained = b"retained unreadable legacy state";
    std::fs::write(&legacy_path, retained).unwrap();
    // Match the projection-only fallback used by Runtime::load_state. The
    // catalog, rather than this placeholder, remains the recovery authority.
    let primary = Arc::new(
        factory(
            StateStore::new(&legacy_path),
            DesktopState {
                last_error: Some("Drive cannot read its retained connection state: test".into()),
                ..DesktopState::default()
            },
        )
        .unwrap(),
    );
    let restarted = ConnectionManager::load(Arc::clone(&primary), factory).unwrap();
    assert!(restarted.resolve(None).is_err());
    assert!(Arc::ptr_eq(&restarted.app_service_runtime(), &primary));
    let view = restarted
        .save_preferences("dark".to_string(), false, 60)
        .unwrap();
    assert_eq!(view.preferences.theme, "dark");
    assert_eq!(view.preferences.default_sync_interval_seconds, 60);
    assert!(restarted.may_sync(&restarted.resolve(Some(&healthy)).unwrap()));
    assert_eq!(std::fs::read(&legacy_path).unwrap(), retained);
    assert!(primary.save().is_err());
    assert_eq!(std::fs::read(&legacy_path).unwrap(), retained);
}

#[test]
fn invalid_derived_id_and_failed_catalog_save_cannot_publish_memory_changes() {
    let harness = Harness::fresh();
    harness.preferences();
    assert!(harness.manager.resolve(Some("../../state.json")).is_err());
    assert!(harness
        .manager
        .reserve_identity(
            "../outside",
            "https://drive.example.test",
            "work@example.test"
        )
        .is_err());
    let before = harness.manager.preferences();
    let catalog_path = harness
        .directory
        .path()
        .join(".shellx-drive-private/connections-v1/catalog.json");
    std::fs::remove_file(&catalog_path).unwrap();
    std::fs::create_dir(&catalog_path).unwrap();
    assert!(harness
        .manager
        .save_preferences("dark".to_string(), true, 60)
        .is_err());
    assert_eq!(harness.manager.preferences(), before);
}

#[cfg(unix)]
#[test]
fn symlinked_catalog_is_rejected_without_overwriting_its_target() {
    let harness = Harness::fresh();
    harness.preferences();
    let catalog_path = harness
        .directory
        .path()
        .join(".shellx-drive-private/connections-v1/catalog.json");
    let target = harness.directory.path().join("unrelated.json");
    std::fs::write(&target, b"retained unrelated bytes").unwrap();
    std::fs::remove_file(&catalog_path).unwrap();
    std::os::unix::fs::symlink(&target, &catalog_path).unwrap();
    assert!(harness
        .manager
        .save_preferences("dark".to_string(), true, 60)
        .is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"retained unrelated bytes");
    assert!(ConnectionManager::load(Arc::clone(&harness.manager.primary), factory).is_err());
}

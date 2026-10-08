use super::*;

#[test]
fn device_credentials_legacy_single_owner_migrates_without_changing_enrollment_or_journal() {
    let harness = Harness::legacy();
    let primary = harness.manager.resolve(None).unwrap();
    let mut state = primary.coordinator.snapshot();
    state
        .desktop_agent_control
        .record_lease(
            "command_fixture".into(),
            "lease_fixture".into(),
            DesktopAgentCommandKind::SetPaused,
            chrono::Utc::now(),
        )
        .unwrap();
    primary.store.save(&state).unwrap();
    primary
        .coordinator
        .begin_lifecycle_operation()
        .unwrap()
        .finish_state(state.clone());
    let restarted = harness.restart();
    let runtime = restarted.resolve(None).unwrap();
    let saved = runtime.store.load().unwrap();
    assert_eq!(
        saved.desktop_agent_control.pair_fingerprint,
        state.desktop_agent_control.pair_fingerprint
    );
    assert_eq!(
        saved.desktop_agent_control.command_journal,
        state.desktop_agent_control.command_journal
    );
    assert_eq!(
        saved.desktop_agent_control.device_id,
        state.desktop_agent_control.device_id
    );
    assert_eq!(
        device_credential(&runtime).unwrap().1,
        "sxd_device_original"
    );
    assert!(harness
        .credentials
        .values
        .get("device_shared")
        .unwrap()
        .is_none());
    assert!(saved.desktop_agent_control.credential_key.is_some());
    assert!(!restarted.has_unavailable_connections());
}

#[test]
fn device_credentials_legacy_ambiguous_owners_never_read_write_or_delete_the_bare_slot() {
    let harness = Harness::legacy();
    let other_id = harness.add_legacy();
    harness.credentials.operations.lock().unwrap().clear();
    let restarted = harness.restart();
    assert!(harness
        .credentials
        .operations
        .lock()
        .unwrap()
        .iter()
        .all(|operation| !operation.ends_with(":device_shared")));
    for runtime in [
        restarted.resolve(None).unwrap(),
        restarted.resolve(Some(&other_id)).unwrap(),
    ] {
        assert!(device_credential(&runtime).is_err());
        assert!(scoped_device_cleanup_slot(&runtime.coordinator.snapshot()).is_err());
        assert!(runtime
            .store
            .load()
            .unwrap()
            .desktop_agent_control
            .credential_key
            .is_none());
    }
    assert!(restarted
        .view()
        .connections
        .iter()
        .all(|connection| connection.view.error.as_deref() == Some(RECOVERY)));
    assert_eq!(
        harness
            .credentials
            .values
            .get("device_shared")
            .unwrap()
            .as_deref(),
        Some("sxd_device_original")
    );
}

#[test]
fn device_credentials_legacy_unreadable_connection_reserves_possible_ownership() {
    let harness = Harness::legacy();
    let id = harness.add_legacy();
    let path = harness
        .manager
        .resolve(Some(&id))
        .unwrap()
        .store
        .path()
        .to_path_buf();
    std::fs::write(path, b"retained unreadable fixture").unwrap();
    harness.credentials.operations.lock().unwrap().clear();
    let restarted = harness.restart();
    assert!(restarted.has_unavailable_connections());
    assert!(restarted
        .resolve(None)
        .unwrap()
        .coordinator
        .snapshot()
        .desktop_agent_control
        .credential_key
        .is_none());
    assert!(harness
        .credentials
        .operations
        .lock()
        .unwrap()
        .iter()
        .all(|operation| !operation.ends_with(":device_shared")));
    assert_eq!(
        harness
            .credentials
            .values
            .get("device_shared")
            .unwrap()
            .as_deref(),
        Some("sxd_device_original")
    );
}

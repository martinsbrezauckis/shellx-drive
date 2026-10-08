use super::*;

#[test]
fn device_credentials_legacy_pending_disconnect_migrates_its_exact_slot_and_preserves_completion() {
    let harness = Harness::legacy();
    let runtime = harness.manager.resolve(None).unwrap();
    let mut state = runtime.coordinator.snapshot();
    let mut intent = DisconnectCleanupIntent::for_disconnect(
        None,
        vec![DisconnectCredentialSlot {
            namespace: DisconnectCredentialNamespace::DesktopAgentDevice,
            account_key: "device_shared".into(),
        }],
    )
    .unwrap();
    intent.confirm_remote_retirement();
    state.pending_disconnect_cleanup = Some(intent);
    state.pair = None;
    state.retire_desktop_agent_control();
    state.pending_desktop_agent_disconnect = Some(
        shellx_drive_desktop_core::DesktopAgentDisconnectContinuation {
            canonical_server_origin: "https://first.example.test".into(),
            command_id: "command_disconnect".into(),
            lease_id: "lease_disconnect".into(),
            retirement_expires_at: None,
            completion_expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            completion_event_sequence: 3,
            phase: shellx_drive_desktop_core::DesktopAgentDisconnectPhase::LocalCleanup,
            retire_assertion: None,
            bound_owner_session: None,
            terminal_receipt: None,
            blocked_reason: None,
        },
    );
    let capability_key = shellx_drive_desktop_core::desktop_agent_disconnect_credential_key(
        "https://first.example.test",
        "command_disconnect",
    );
    harness
        .credentials
        .values
        .set(&capability_key, "sxd_disconnect_fixture")
        .unwrap();
    runtime.store.save(&state).unwrap();
    runtime
        .coordinator
        .begin_lifecycle_operation()
        .unwrap()
        .finish_state(state.clone());
    let restarted = harness.restart();
    let saved = restarted.resolve(None).unwrap().store.load().unwrap();
    let slot = saved
        .pending_disconnect_cleanup()
        .unwrap()
        .next_credential_slot()
        .unwrap();
    assert_eq!(
        slot.namespace,
        DisconnectCredentialNamespace::DesktopAgentDeviceScoped
    );
    assert_eq!(
        harness
            .credentials
            .values
            .get(&slot.account_key)
            .unwrap()
            .as_deref(),
        Some("sxd_device_original")
    );
    assert_eq!(
        saved.pending_desktop_agent_disconnect(),
        state.pending_desktop_agent_disconnect()
    );
    assert_eq!(
        harness
            .credentials
            .values
            .get(&capability_key)
            .unwrap()
            .as_deref(),
        Some("sxd_disconnect_fixture")
    );
    assert!(saved
        .pending_disconnect_cleanup()
        .unwrap()
        .remote_retirement_confirmed());
    assert!(harness
        .credentials
        .values
        .get("device_shared")
        .unwrap()
        .is_none());
}

#[test]
fn device_credentials_legacy_historical_root_fingerprint_is_preserved() {
    let harness = Harness::legacy();
    let runtime = harness.manager.resolve(None).unwrap();
    let mut state = runtime.coordinator.snapshot();
    state.pair.as_mut().unwrap().server_url = "https://FIRST.example.test/".into();
    let fingerprint = desktop_agent_pair_fingerprint(state.pair.as_ref().unwrap());
    state.desktop_agent_control.pair_fingerprint = Some(fingerprint.clone());
    runtime.store.save(&state).unwrap();
    runtime
        .coordinator
        .begin_lifecycle_operation()
        .unwrap()
        .finish_state(state);
    let restarted = harness.restart();
    let runtime = restarted.resolve(None).unwrap();
    assert_eq!(
        runtime
            .coordinator
            .snapshot()
            .desktop_agent_control
            .pair_fingerprint
            .as_deref(),
        Some(fingerprint.as_str())
    );
    assert_eq!(
        device_credential(&runtime).unwrap().1,
        "sxd_device_original"
    );
}

#[test]
fn device_credentials_legacy_copy_survives_state_save_failure_and_conflicts_are_retained() {
    let harness = Harness::legacy();
    let runtime = harness.manager.resolve(None).unwrap();
    let state = runtime.coordinator.snapshot();
    let identity = runtime.current_session().unwrap();
    let migrated = migrate_owned_state(&state, &identity, harness.credentials.as_ref()).unwrap();
    let key = migrated
        .desktop_agent_control
        .credential_key
        .clone()
        .unwrap();
    // Simulate a failed state publication after the protected copy moved. The
    // real loader must recover from the still-durable old enrollment.
    assert!(runtime
        .store
        .load()
        .unwrap()
        .desktop_agent_control
        .credential_key
        .is_none());
    let restarted = harness.restart();
    assert_eq!(
        device_credential(&restarted.resolve(None).unwrap())
            .unwrap()
            .1,
        "sxd_device_original"
    );
    assert_eq!(
        harness.credentials.values.get(&key).unwrap().as_deref(),
        Some("sxd_device_original")
    );

    let conflict = Harness::legacy();
    conflict
        .credentials
        .values
        .set(&key, "sxd_device_conflicting")
        .unwrap();
    let restarted = conflict.restart();
    assert!(restarted
        .resolve(None)
        .unwrap()
        .coordinator
        .snapshot()
        .desktop_agent_control
        .credential_key
        .is_none());
    assert_eq!(
        conflict
            .credentials
            .values
            .get("device_shared")
            .unwrap()
            .as_deref(),
        Some("sxd_device_original")
    );
    assert_eq!(
        conflict.credentials.values.get(&key).unwrap().as_deref(),
        Some("sxd_device_conflicting")
    );
}

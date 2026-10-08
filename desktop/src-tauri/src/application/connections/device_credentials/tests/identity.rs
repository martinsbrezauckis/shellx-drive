use super::*;

#[test]
fn device_credentials_legacy_identity_delimiters_cannot_alias_protected_store_slots() {
    let store = MemoryStore::default();
    let root = tempfile::tempdir().unwrap();
    let mut first = old_state(
        root.path(),
        "https://drive.example.test/a|b",
        "c@example.test",
    );
    let mut second = old_state(
        root.path(),
        "https://drive.example.test/a",
        "b|c@example.test",
    );
    let first_identity = state_identity(&first).unwrap().unwrap().session();
    let second_identity = state_identity(&second).unwrap().unwrap().session();
    store
        .values
        .set("device_shared", "sxd_device_first")
        .unwrap();
    first = migrate_owned_state(&first, &first_identity, &store).unwrap();
    store
        .values
        .set("device_shared", "sxd_device_second")
        .unwrap();
    second = migrate_owned_state(&second, &second_identity, &store).unwrap();
    let first_slot = scoped_device_cleanup_slot(&first).unwrap().unwrap();
    let second_slot = scoped_device_cleanup_slot(&second).unwrap().unwrap();
    assert_ne!(first_slot, second_slot);
    assert_eq!(
        store
            .values
            .get(&first_slot.account_key)
            .unwrap()
            .as_deref(),
        Some("sxd_device_first")
    );
    assert_eq!(
        store
            .values
            .get(&second_slot.account_key)
            .unwrap()
            .as_deref(),
        Some("sxd_device_second")
    );
    crate::application::desktop_agent::remove_exact_agent_credential(
        &store,
        &first_slot.account_key,
    )
    .unwrap();
    assert_eq!(
        store
            .values
            .get(&second_slot.account_key)
            .unwrap()
            .as_deref(),
        Some("sxd_device_second")
    );
}

#[tokio::test]
async fn device_credentials_locator_shaped_remote_id_is_rejected_before_store_publication() {
    let harness = Harness::legacy();
    let runtime = harness.manager.resolve(None).unwrap();
    let mut state = runtime.coordinator.snapshot();
    state.retire_desktop_agent_control();
    let target = desktop_agent_device_credential_key(&"a".repeat(64), "victim_device").unwrap();
    harness
        .credentials
        .values
        .set(&target, "sxd_device_victim")
        .unwrap();
    runtime.store.save(&state).unwrap();
    runtime
        .coordinator
        .begin_lifecycle_operation()
        .unwrap()
        .finish_state(state);
    harness.credentials.operations.lock().unwrap().clear();
    let pair = runtime.coordinator.snapshot().pair.unwrap();
    let registration = shellx_drive_desktop_core::DesktopAgentRegistration {
        device_id: target.clone(),
        device_credential: "sxd_device_attacker".into(),
        credential_expires_at: None,
    };
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    let result = crate::application::desktop_agent::publish_registered_agent(
        &runtime,
        &mut operation,
        &registration,
        desktop_agent_enrollment_fingerprint(&pair.server_url, &pair.account_email),
        || async { panic!("invalid registration must not reach broker retirement") },
    )
    .await;
    assert!(matches!(result, Err(DesktopError::InvalidState(_))));
    assert!(harness.credentials.operations.lock().unwrap().is_empty());
    assert!(!runtime.coordinator.snapshot().desktop_agent_control.enabled);
    assert_eq!(
        harness.credentials.values.get(&target).unwrap().as_deref(),
        Some("sxd_device_victim")
    );
}

use super::*;

fn paired_runtime() -> (
    tempfile::TempDir,
    Arc<FakeCredentialStore>,
    Runtime,
    SessionIdentity,
) {
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let mut state = DesktopState::default();
    state.configure_pair(pair("existing")).unwrap();
    state.baseline.insert(
        "kept".to_string(),
        BaselineEntry {
            remote_id: "kept".to_string(),
            parent_id: None,
            relative_path: "kept".into(),
            kind: "file".to_string(),
            content_hash: None,
            revision: 7,
            directory_identity: None,
        },
    );
    state.configure_pair(pair("selected")).unwrap();
    store.save(&state).unwrap();
    let credentials = Arc::new(FakeCredentialStore::default());
    let identity = SessionIdentity::new("https://drive.example.test", "person@example.test");
    credentials
        .set(&identity.credential_key(), "captured")
        .unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(Arc::clone(&credentials))),
        store,
        state,
    );
    *runtime.session.lock().unwrap() = Some(identity.clone());
    (directory, credentials, runtime, identity)
}

fn assert_admission_preserves_state(
    runtime: &Runtime,
    credentials: &FakeCredentialStore,
    identity: &SessionIdentity,
    accepted: bool,
) {
    let before = runtime.coordinator.snapshot();
    let stored_before = runtime.store.load().unwrap();
    let bearer_before = credentials.get(&identity.credential_key()).unwrap();
    let publication = tauri::async_runtime::block_on(runtime.auth_publication.lock());
    let result = runtime.require_captured_setup_session_during_publication(identity, "captured");
    drop(publication);
    if accepted {
        result.expect("the exact retained pair session must admit another root");
    } else {
        assert!(matches!(result, Err(DesktopError::NeedsReconnect)));
    }
    assert_eq!(runtime.coordinator.snapshot(), before);
    assert_eq!(runtime.store.load().unwrap(), stored_before);
    assert_eq!(
        credentials.get(&identity.credential_key()).unwrap(),
        bearer_before
    );
}

#[test]
fn paired_add_root_admits_current_session_without_clearing_existing_pairs() {
    let (_directory, credentials, runtime, identity) = paired_runtime();
    let _operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    assert_admission_preserves_state(&runtime, &credentials, &identity, true);
    let state = runtime.coordinator.snapshot();
    assert_eq!(state.inactive_pairs.len(), 1);
    assert_eq!(state.inactive_pairs[0].baseline["kept"].revision, 7);
}

#[test]
fn restored_pair_add_root_admits_identity_without_an_ephemeral_session() {
    let (_directory, credentials, runtime, identity) = paired_runtime();
    *runtime.session.lock().unwrap() = None;
    assert_eq!(runtime.current_session().unwrap(), identity);
    assert_admission_preserves_state(&runtime, &credentials, &identity, true);
}

#[test]
fn paired_add_root_rejects_wrong_account_or_server_even_with_matching_ephemeral_session() {
    for wrong in [
        SessionIdentity::new("https://drive.example.test", "another@example.test"),
        SessionIdentity::new("https://other.example.test", "person@example.test"),
    ] {
        let (_directory, credentials, runtime, identity) = paired_runtime();
        credentials
            .set(&wrong.credential_key(), "captured")
            .unwrap();
        assert_admission_preserves_state(&runtime, &credentials, &wrong, false);
        *runtime.session.lock().unwrap() = Some(wrong.clone());
        assert_admission_preserves_state(&runtime, &credentials, &wrong, false);
        assert_admission_preserves_state(&runtime, &credentials, &identity, false);
    }
}

#[test]
fn paired_add_root_rejects_rotated_or_removed_captured_bearer() {
    for replacement in [Some("rotated"), None] {
        let (_directory, credentials, runtime, identity) = paired_runtime();
        match replacement {
            Some(value) => credentials.set(&identity.credential_key(), value).unwrap(),
            None => credentials.delete(&identity.credential_key()).unwrap(),
        }
        assert_admission_preserves_state(&runtime, &credentials, &identity, false);
        *runtime.session.lock().unwrap() = None;
        assert_admission_preserves_state(&runtime, &credentials, &identity, false);
    }
}

#[test]
fn disconnect_invalidates_inflight_add_root_and_rejects_stale_retained_bearer() {
    let (_directory, credentials, runtime, identity) = paired_runtime();
    let generation = runtime.auth_offboarding.admit_login().unwrap();
    let latch = runtime.auth_offboarding.begin_offboarding().unwrap();
    assert!(!runtime.auth_offboarding.may_publish(generation));
    assert!(runtime.auth_offboarding.admit_login().is_err());
    let publication = tauri::async_runtime::block_on(runtime.auth_publication.lock());
    runtime.coordinator.disconnect().unwrap();
    *runtime.session.lock().unwrap() = None;
    runtime.save().unwrap();
    drop(publication);
    assert_admission_preserves_state(&runtime, &credentials, &identity, false);
    drop(latch);
    assert!(!runtime.auth_offboarding.may_publish(generation));
    assert!(runtime.coordinator.snapshot().pair.is_none());
}

#[test]
fn cleared_unpaired_setup_session_rejects_its_old_bearer() {
    let (_directory, credentials, runtime, identity) = paired_runtime();
    runtime.coordinator.disconnect().unwrap();
    runtime.save().unwrap();
    assert_admission_preserves_state(&runtime, &credentials, &identity, true);
    *runtime.session.lock().unwrap() = None;
    assert_admission_preserves_state(&runtime, &credentials, &identity, false);
}

use super::*;

fn runtime(state: DesktopState) -> Runtime {
    Runtime::from_loaded_state(
        Box::new(crate::platform::windows::WindowsPlatformServices::default()),
        StateStore::new(std::env::temp_dir().join("unused-drive-connection-state.json")),
        state,
    )
}

#[test]
fn rejected_duplicate_owns_only_its_exact_candidate_slot() {
    let candidate = RemoteSessionRecord::new(
        "https://drive.example.test",
        "owner@example.test",
        "rejected-session",
        Utc::now() + chrono::Duration::hours(1),
    )
    .unwrap();
    let state = DesktopState {
        pending_candidate_session: Some(candidate.clone()),
        ..DesktopState::default()
    };
    let runtime = runtime(state.clone());
    assert!(owned_canonical_keys(&runtime, &state, None).is_empty());
    let slots = owned_pending_slots(&state).unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].session_id, candidate.session_id);
    assert!(!slots
        .iter()
        .any(|slot| slot.session_id == "existing-connection-session"));
}

#[test]
fn catalog_identity_keeps_unpaired_candidate_cleanup_scoped() {
    let owned = SessionIdentity::new("https://drive.example.test", "work@example.test");
    let other = RemoteSessionRecord::new(
        "https://drive.example.test",
        "personal@example.test",
        "other-session",
        Utc::now() + chrono::Duration::hours(1),
    )
    .unwrap();
    let candidate = RemoteSessionRecord::new(
        &owned.server_url,
        &owned.email,
        "work-session",
        Utc::now() + chrono::Duration::hours(1),
    )
    .unwrap();
    let state = DesktopState {
        pending_candidate_session: Some(candidate),
        pending_remote_revocations: vec![other],
        ..DesktopState::default()
    };
    let runtime = runtime(state.clone());
    runtime.set_owned_session_identity(owned.clone());
    assert_eq!(
        owned_canonical_keys(&runtime, &state, None)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![owned.credential_key()]
    );
}

#[test]
fn fresh_candidate_keeps_expired_exact_slot_ownership_after_restart() {
    let now = Utc::now();
    let expired = RemoteSessionRecord::new(
        "https://drive.example.test",
        "work@example.test",
        "expired-staged-session",
        now - chrono::Duration::hours(1),
    )
    .unwrap();
    let fresh = RemoteSessionRecord::new(
        &expired.server_url,
        &expired.account_email,
        "fresh-session",
        now + chrono::Duration::hours(1),
    )
    .unwrap();
    let old = DesktopState {
        pending_candidate_session: Some(expired.clone()),
        ..DesktopState::default()
    };
    let prepared =
        crate::application::candidate_admission::prepare_candidate_state(&old, &fresh, now)
            .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    store.save(&prepared).unwrap();
    let loaded = store.load().unwrap();
    let slots = owned_pending_slots(&loaded).unwrap();
    assert_eq!(slots.len(), 2);
    for session_id in [&expired.session_id, &fresh.session_id] {
        assert!(slots.iter().any(|slot| &slot.session_id == session_id));
    }
    assert!(old.pending_remote_revocations.is_empty());
    assert!(old
        .pending_candidate_session
        .unwrap()
        .same_remote_session(&expired));
}

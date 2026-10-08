use chrono::Duration;

use super::*;

fn record(session_id: &str, expires_at: DateTime<Utc>) -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        "https://drive.example.test",
        "person@example.test",
        session_id,
        expires_at,
    )
    .unwrap()
}

#[test]
fn fresh_candidate_preserves_expired_exact_slot_locators_through_restart() {
    let now = Utc::now();
    let expired = record("expired-candidate", now - Duration::hours(1));
    let older = record("expired-revocation", now - Duration::hours(2));
    let active = record("expired-active", now - Duration::minutes(1));
    let fresh = record("fresh", now + Duration::hours(1));
    let state = DesktopState {
        pending_candidate_session: Some(expired.clone()),
        active_remote_session: Some(active.clone()),
        pending_remote_revocations: vec![older.clone()],
        ..DesktopState::default()
    };
    let prepared = prepare_candidate_state(&state, &fresh, now).unwrap();
    assert_eq!(state.pending_candidate_session, Some(expired.clone()));
    let directory = tempfile::tempdir().unwrap();
    let store = shellx_drive_desktop_core::StateStore::new(directory.path().join("state.json"));
    store.save(&prepared).unwrap();
    let restarted = store.load().unwrap();
    assert_eq!(restarted.pending_candidate_session, Some(fresh));
    assert_eq!(restarted.active_remote_session, Some(active));
    assert_eq!(restarted.pending_remote_revocations, [older, expired]);
}

#[test]
fn full_locator_inventory_rejects_fresh_admission_without_eviction_or_mutation() {
    let now = Utc::now();
    let old = record("owned-pending", now - Duration::hours(1));
    let fresh = record("fresh", now + Duration::hours(1));
    let state = DesktopState {
        pending_candidate_session: Some(old.clone()),
        pending_remote_revocations: (0..MAX_PENDING_REMOTE_REVOCATIONS)
            .map(|index| record(&format!("owned-{index}"), now - Duration::hours(2)))
            .collect(),
        ..DesktopState::default()
    };
    let original = serde_json::to_vec(&state).unwrap();
    assert!(ensure_candidate_admission(&state).is_err());
    assert!(prepare_candidate_state(&state, &fresh, now).is_err());
    assert_eq!(serde_json::to_vec(&state).unwrap(), original);

    let mut duplicate = state;
    duplicate.pending_remote_revocations[0] = old;
    ensure_candidate_admission(&duplicate).unwrap();
    let prepared = prepare_candidate_state(&duplicate, &fresh, now).unwrap();
    assert_eq!(
        prepared.pending_remote_revocations.len(),
        MAX_PENDING_REMOTE_REVOCATIONS
    );
}

#[test]
fn expired_new_session_is_rejected_before_staging() {
    let now = Utc::now();
    let state = DesktopState::default();
    assert!(prepare_candidate_state(&state, &record("expired", now), now).is_err());
    assert!(state.pending_candidate_session.is_none());
}

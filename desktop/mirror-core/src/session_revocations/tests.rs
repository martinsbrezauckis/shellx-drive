use super::*;
use chrono::Duration;

#[path = "tests/local_bearer.rs"]
mod local_bearer;

fn record(id: &str, expires_at: DateTime<Utc>) -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        "https://drive.example.test",
        "Person@Example.Test",
        id,
        expires_at,
    )
    .unwrap()
}

#[test]
fn pending_records_are_non_secret_bounded_and_pruned() {
    let now = Utc::now();
    let mut state = DesktopState::default();
    state.record_pending_remote_revocation(record("expired", now), now);
    for index in 0..=MAX_PENDING_REMOTE_REVOCATIONS {
        state.record_pending_remote_revocation(
            record(
                &format!("session-{index}"),
                now + Duration::hours(index as i64 + 1),
            ),
            now,
        );
    }
    assert_eq!(
        state.pending_remote_revocations.len(),
        MAX_PENDING_REMOTE_REVOCATIONS
    );
    assert!(!state
        .pending_remote_revocations
        .iter()
        .any(|entry| entry.session_id == "session-0"));
    let json = serde_json::to_string(&state).unwrap();
    assert!(!json.contains("bearer"));
    assert!(!json.contains("token"));
}

#[test]
fn server_and_account_identity_are_canonical_and_transport_safe() {
    let expires_at = Utc::now() + Duration::hours(1);
    let canonical = RemoteSessionRecord::new(
        "HTTPS://Drive.Example.Test/",
        " Person@Example.Test ",
        "session-42",
        expires_at,
    )
    .unwrap();
    assert_eq!(canonical.server_url, "https://drive.example.test");
    assert_eq!(canonical.account_email, "person@example.test");
    assert!(RemoteSessionRecord::new(
        "http://drive.example.test",
        "person@example.test",
        "session-42",
        expires_at,
    )
    .is_err());
    assert!(RemoteSessionRecord::new(
        "http://127.0.0.1:8787",
        "person@example.test",
        "session-42",
        expires_at,
    )
    .is_err());
}

#[test]
fn disconnect_moves_only_nonsecret_active_metadata_to_pending() {
    let now = Utc::now();
    let active = record("active-session", now + Duration::hours(1));
    let state = DesktopState {
        active_remote_session: Some(active.clone()),
        ..DesktopState::default()
    }
    .into_disconnected(now);
    assert!(state.active_remote_session.is_none());
    assert_eq!(state.pending_remote_revocations, vec![active]);
    assert!(state.pair.is_none());
}

#[test]
fn retry_selection_is_exact_to_canonical_server_and_account() {
    let now = Utc::now();
    let selected = record("selected", now + Duration::hours(1));
    let other = RemoteSessionRecord::new(
        "https://other.example.test",
        "other@example.test",
        "other",
        now + Duration::hours(1),
    )
    .unwrap();
    let state = DesktopState {
        pending_remote_revocations: vec![selected.clone(), other],
        ..DesktopState::default()
    };
    assert_eq!(
        state.pending_remote_revocations_for_identity(
            "HTTPS://DRIVE.EXAMPLE.TEST/",
            "person@example.test",
            now,
        ),
        vec![selected]
    );
}

#[test]
fn publishing_the_same_session_removes_it_from_pending_without_retiring_it() {
    let now = Utc::now();
    let candidate = record("same-session", now + Duration::hours(1));
    let stale_expiry = record("same-session", now + Duration::minutes(30));
    let mut state = DesktopState {
        pending_remote_revocations: vec![stale_expiry],
        ..DesktopState::default()
    };
    state.publish_active_remote_session(candidate.clone());
    assert_eq!(state.active_remote_session, Some(candidate));
    assert!(state.pending_remote_revocations.is_empty());
}

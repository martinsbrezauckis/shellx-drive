use chrono::{Duration, Utc};
use shellx_drive_desktop_core::DriveHttpClient;

use super::*;

fn record(server_url: &str, email: &str, session_id: &str) -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        server_url,
        email,
        session_id,
        Utc::now() + Duration::hours(1),
    )
    .unwrap()
}

#[test]
fn legacy_slots_preserve_pipe_paths_and_email_local_parts() {
    let client = DriveHttpClient::new("https://drive.example.test/tenant|suffix").unwrap();
    let saved = record(
        client.normalized_url(),
        "alice|tag@example.test",
        "saved-session",
    );
    let expected = SessionIdentity::new(&saved.server_url, &saved.account_email);
    let pending = expected.pending_service_key(&saved.session_id).unwrap();
    let state = DesktopState {
        active_remote_session: Some(saved),
        ..DesktopState::default()
    };
    assert_eq!(
        client.normalized_url(),
        "https://drive.example.test/tenant|suffix"
    );
    assert_eq!(
        canonical_credential_identity(&state, &expected.credential_key()).unwrap(),
        expected
    );
    assert_eq!(
        pending_credential_slot(&state, &pending.account_key).unwrap(),
        pending
    );
}

#[test]
fn colliding_legacy_keys_do_not_select_either_service_identity() {
    let original = record(
        "https://drive.example.test/tenant|suffix",
        "alice@example.test",
        "same-id",
    );
    let shifted = record(
        "https://drive.example.test/tenant",
        "suffix|alice@example.test",
        "same-id",
    );
    let expected = SessionIdentity::new(&original.server_url, &original.account_email);
    assert_eq!(
        expected.credential_key(),
        SessionIdentity::new(&shifted.server_url, &shifted.account_email).credential_key()
    );
    let pending = expected.pending_service_key("same-id").unwrap();
    let state = DesktopState {
        active_remote_session: Some(original),
        pending_candidate_session: Some(shifted),
        ..DesktopState::default()
    };
    assert!(canonical_credential_identity(&state, &expected.credential_key()).is_err());
    assert!(pending_credential_slot(&state, &pending.account_key).is_err());
}

#[test]
fn syntactically_valid_but_unattributed_keys_remain_unresolved() {
    let identity = SessionIdentity::new("https://drive.example.test", "alice|tag@example.test");
    let pending = identity.pending_service_key("unattributed").unwrap();
    let state = DesktopState::default();
    assert!(canonical_credential_identity(&state, &identity.credential_key()).is_err());
    assert!(pending_credential_slot(&state, &pending.account_key).is_err());
}

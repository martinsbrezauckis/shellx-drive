use super::*;
use shellx_drive_desktop_core::{CredentialStore, FakeCredentialStore};

#[test]
fn two_pre_pair_identities_round_trip_and_retire_even_if_tokens_match() {
    let previous = SessionIdentity::new("https://drive.example.test", "one@example.test");
    let next = SessionIdentity::new("https://drive.example.test", "two@example.test");

    assert_eq!(
        SessionIdentity::parse_canonical_credential_key(&previous.credential_key()),
        Some(previous)
    );
    assert_ne!(
        next.credential_key(),
        "https://drive.example.test|one@example.test"
    );
    assert!(stored_credential_needs_remote_retirement(
        &SessionIdentity::new("https://drive.example.test", "one@example.test"),
        "old-token",
        Some((&next, "old-token"))
    ));
}

#[test]
fn same_key_token_replacement_retires_only_a_distinct_previous_token() {
    let previous = SessionIdentity::new("https://drive.example.test/", " Person@Example.Test ");
    let next = SessionIdentity::new("https://drive.example.test", "person@example.test");

    assert_eq!(previous.credential_key(), next.credential_key());
    assert!(stored_credential_needs_remote_retirement(
        &previous,
        "old-token",
        Some((&next, "new-token"))
    ));
    assert!(!stored_credential_needs_remote_retirement(
        &previous,
        "same-token",
        Some((&next, "same-token"))
    ));
}

#[test]
fn pending_service_key_preserves_the_canonical_bearer_and_email_delimiters() {
    let identity = SessionIdentity::new("https://drive.example.test", "person|tag@example.test");
    let canonical = identity.credential_key();
    let pending = identity.pending_service_key("candidate_42").unwrap();

    assert_ne!(canonical, pending.account_key);
    assert_eq!(
        SessionIdentity::parse_pending_service_key(&pending.account_key),
        Some(pending)
    );
    assert!(SessionIdentity::parse_canonical_credential_key(
        "https://drive.example.test/|person@example.test"
    )
    .is_none());
}

#[test]
fn ambiguous_candidate_slot_never_replaces_the_existing_same_identity_bearer() {
    let identity = SessionIdentity::new("https://drive.example.test", "person@example.test");
    let canonical = identity.credential_key();
    let candidate = identity.pending_service_key("candidate_42").unwrap();
    let credentials = FakeCredentialStore::default();

    credentials.set(&canonical, "old-valid-bearer").unwrap();
    credentials
        .set(&candidate.account_key, "ambiguous-candidate-bearer")
        .unwrap();

    assert_eq!(
        credentials.get(&canonical).unwrap().as_deref(),
        Some("old-valid-bearer")
    );
    assert_eq!(
        credentials.get(&candidate.account_key).unwrap().as_deref(),
        Some("ambiguous-candidate-bearer")
    );
}

#[test]
fn disconnect_prefers_the_live_session_and_falls_back_to_the_pair() {
    let session = SessionIdentity::new("https://current.example", "current@example.test");
    let pair = SessionIdentity::new("https://paired.example", "paired@example.test");

    assert_eq!(
        disconnect_identity(Some(session.clone()), Some(pair.clone())),
        Some(session)
    );
    assert_eq!(disconnect_identity(None, Some(pair.clone())), Some(pair));
    assert_eq!(disconnect_identity(None, None), None);
    assert!(stored_credential_needs_remote_retirement(
        &SessionIdentity::new("https://drive.example.test", "person@example.test"),
        "setup-token",
        None
    ));
}

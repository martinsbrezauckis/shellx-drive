use std::future::ready;

use chrono::{Duration, Utc};
use shellx_drive_desktop_core::{
    DisconnectCleanupIntent, DisconnectCredentialNamespace, DisconnectCredentialSlot,
    FakeCredentialStore,
};

use super::*;

fn record(server_url: &str, email: &str) -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        server_url,
        email,
        "saved-session",
        Utc::now() + Duration::hours(1),
    )
    .unwrap()
}

#[test]
fn canonical_and_pending_cleanup_send_only_the_durable_full_url() {
    for namespace in [
        DisconnectCredentialNamespace::Canonical,
        DisconnectCredentialNamespace::PendingCandidate,
    ] {
        let saved = record(
            "https://drive.example.test/tenant|suffix",
            "alice|tag@example.test",
        );
        let identity = SessionIdentity::new(&saved.server_url, &saved.account_email);
        let key = match namespace {
            DisconnectCredentialNamespace::Canonical => identity.credential_key(),
            _ => {
                identity
                    .pending_service_key(&saved.session_id)
                    .unwrap()
                    .account_key
            }
        };
        let canonical = FakeCredentialStore::default();
        let pending = FakeCredentialStore::default();
        let credentials: &dyn CredentialStore = match namespace {
            DisconnectCredentialNamespace::Canonical => &canonical,
            _ => &pending,
        };
        credentials
            .set(&key, "synthetic-retirement-bearer")
            .unwrap();
        let mut state = DesktopState {
            active_remote_session: Some(saved.clone()),
            ..DesktopState::default()
        };
        state
            .begin_disconnect_cleanup(
                DisconnectCleanupIntent::for_disconnect_pairs(
                    Vec::new(),
                    vec![DisconnectCredentialSlot {
                        namespace,
                        account_key: key.clone(),
                    }],
                )
                .unwrap(),
            )
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::new(directory.path().join("state.json"));
        store.save(&state).unwrap();
        let stored = load_stored_credentials_from(&state, &canonical, &pending).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].identity, identity);
        let mut logout_urls = Vec::new();
        tauri::async_runtime::block_on(retire_stored_sessions(
            &store,
            &mut state,
            &stored,
            |_, _| -> std::future::Ready<CoreResult<RemoteSessionRevocationOutcome>> {
                panic!("the exact direct session is retired by logout")
            },
            |credential| {
                logout_urls.push(credential.identity.server_url.clone());
                assert_eq!(credential.token, "synthetic-retirement-bearer");
                ready(Ok(LogoutOutcome::Revoked))
            },
        ))
        .unwrap();
        assert_eq!(logout_urls, [saved.server_url]);
        assert!(state.active_remote_session.is_none());
        // Remote retirement does not delete the local slot before journal confirmation.
        assert!(credentials.get(&key).unwrap().is_some());
    }
}

struct NoCredentialReads;

impl CredentialStore for NoCredentialReads {
    fn get(&self, _: &str) -> CoreResult<Option<String>> {
        panic!("unresolved identity must not read a bearer")
    }
    fn set(&self, _: &str, _: &str) -> CoreResult<()> {
        panic!("must not write")
    }
    fn delete(&self, _: &str) -> CoreResult<()> {
        panic!("must not delete")
    }
}

#[test]
fn ambiguous_cleanup_identity_fails_before_reading_or_transmitting_a_bearer() {
    let original = record(
        "https://drive.example.test/tenant|suffix",
        "alice@example.test",
    );
    let shifted = record(
        "https://drive.example.test/tenant",
        "suffix|alice@example.test",
    );
    let key = SessionIdentity::new(&original.server_url, &original.account_email).credential_key();
    let mut state = DesktopState {
        active_remote_session: Some(original),
        pending_candidate_session: Some(shifted),
        ..DesktopState::default()
    };
    state
        .begin_disconnect_cleanup(
            DisconnectCleanupIntent::for_disconnect_pairs(
                Vec::new(),
                vec![DisconnectCredentialSlot {
                    namespace: DisconnectCredentialNamespace::Canonical,
                    account_key: key,
                }],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(load_stored_credentials_from(&state, &NoCredentialReads, &NoCredentialReads).is_err());
}

#[test]
fn a_shortened_authorizer_cannot_reach_either_retirement_callback() {
    let saved = record(
        "https://drive.example.test/tenant|suffix",
        "alice@example.test",
    );
    let original = SessionIdentity::new(&saved.server_url, &saved.account_email);
    let shortened =
        SessionIdentity::parse_canonical_credential_key(&original.credential_key()).unwrap();
    assert_ne!(shortened, original);
    let mut state = DesktopState {
        active_remote_session: Some(saved.clone()),
        ..DesktopState::default()
    };
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let stored = [StoredCredential {
        identity: shortened,
        token: "synthetic-retirement-bearer".into(),
        session_id: None,
    }];
    let result = tauri::async_runtime::block_on(retire_stored_sessions(
        &store,
        &mut state,
        &stored,
        |_, _| -> std::future::Ready<CoreResult<RemoteSessionRevocationOutcome>> {
            panic!("mismatched identity must not authorize revocation")
        },
        |_| -> std::future::Ready<CoreResult<LogoutOutcome>> {
            panic!("mismatched identity must not reach logout")
        },
    ));
    assert!(result.is_err());
    assert_eq!(state.active_remote_session, Some(saved));
}

use std::future::ready;

use chrono::{Duration, Utc};
use shellx_drive_desktop_core::{
    CredentialStore, DisconnectCleanupIntent, DisconnectCredentialNamespace,
    DisconnectCredentialSlot, FakeCredentialStore,
};

use super::super::{load_stored_credentials_from, retire_remote_credentials};
use super::*;
use crate::session_identity::SessionIdentity;

fn record(session_id: &str) -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        "https://drive.example.test/tenant|suffix",
        "alice|tag@example.test",
        session_id,
        Utc::now() + Duration::hours(1),
    )
    .unwrap()
}

#[test]
fn partial_logout_or_final_save_failure_retries_without_reauthorizing_old_sessions() {
    for fail_final_save in [false, true] {
        let active = record("canonical-session");
        let pending_record = record("candidate-session");
        let identity = SessionIdentity::new(&active.server_url, &active.account_email);
        let canonical_key = identity.credential_key();
        let pending_key = identity
            .pending_service_key(&pending_record.session_id)
            .unwrap()
            .account_key;
        let canonical = FakeCredentialStore::default();
        let pending = FakeCredentialStore::default();
        canonical
            .set(&canonical_key, "synthetic-canonical-bearer")
            .unwrap();
        pending
            .set(&pending_key, "synthetic-pending-bearer")
            .unwrap();
        let slots = vec![
            DisconnectCredentialSlot {
                namespace: DisconnectCredentialNamespace::Canonical,
                account_key: canonical_key.clone(),
            },
            DisconnectCredentialSlot {
                namespace: DisconnectCredentialNamespace::PendingCandidate,
                account_key: pending_key.clone(),
            },
        ];
        let mut state = DesktopState {
            active_remote_session: Some(active.clone()),
            pending_candidate_session: Some(pending_record.clone()),
            pending_remote_revocations: vec![record("old-session")],
            ..DesktopState::default()
        };
        state
            .begin_disconnect_cleanup(
                DisconnectCleanupIntent::for_disconnect_pairs(Vec::new(), slots.clone()).unwrap(),
            )
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::new(directory.path().join("state.json"));
        store.save(&state).unwrap();
        let stored = load_stored_credentials_from(&state, &canonical, &pending).unwrap();
        let mut events = Vec::new();
        let result = tauri::async_runtime::block_on(retire_with_save(
            &mut state,
            &stored,
            |image| {
                events.push(
                    if image
                        .pending_disconnect_cleanup()
                        .unwrap()
                        .remote_retirement_confirmed()
                    {
                        "confirmation"
                    } else {
                        "prior progress"
                    },
                );
                if fail_final_save
                    && image
                        .pending_disconnect_cleanup()
                        .unwrap()
                        .remote_retirement_confirmed()
                {
                    return Err(DesktopError::InvalidState(
                        "synthetic final-save failure".into(),
                    ));
                }
                store.save(image)
            },
            |credential, old| {
                assert_eq!(old.session_id, "old-session");
                assert_eq!(credential.token, "synthetic-canonical-bearer");
                assert_eq!(credential.identity, identity);
                ready(Ok(RemoteSessionRevocationOutcome::Revoked))
            },
            |credential| {
                assert_eq!(credential.identity, identity);
                if credential.session_id.is_some() && !fail_final_save {
                    return ready(Err(DesktopError::InvalidState(
                        "synthetic pending-logout failure".into(),
                    )));
                }
                ready(Ok(LogoutOutcome::Revoked))
            },
        ));
        assert!(result.is_err());
        assert_eq!(
            events,
            if fail_final_save {
                vec!["prior progress", "confirmation"]
            } else {
                vec!["prior progress"]
            }
        );
        // Old-session progress remains acknowledged. Direct locators remain
        // durable even though their bearers may now be remotely invalid.
        let mut restored = store.load().unwrap();
        assert!(restored.pending_remote_revocations.is_empty());
        assert_eq!(restored.active_remote_session, Some(active));
        assert_eq!(restored.pending_candidate_session, Some(pending_record));
        assert!(!restored
            .pending_disconnect_cleanup()
            .unwrap()
            .remote_retirement_confirmed());
        let stored = load_stored_credentials_from(&restored, &canonical, &pending).unwrap();
        let mut retried = Vec::new();
        tauri::async_runtime::block_on(retire_with_save(
            &mut restored,
            &stored,
            |image| store.save(image),
            |_, _| -> std::future::Ready<CoreResult<RemoteSessionRevocationOutcome>> {
                panic!("acknowledged old revocations must not need an invalid canonical bearer")
            },
            |credential| {
                assert_eq!(credential.identity, identity);
                retried.push(credential.session_id.clone());
                ready(Ok(if credential.session_id.is_none() || fail_final_save {
                    LogoutOutcome::AlreadyInvalid
                } else {
                    LogoutOutcome::Revoked
                }))
            },
        ))
        .unwrap();
        assert_eq!(retried, [None, Some("candidate-session".into())]);
        assert!(restored.active_remote_session.is_none());
        assert!(restored.pending_candidate_session.is_none());
        assert!(restored
            .pending_disconnect_cleanup()
            .unwrap()
            .remote_retirement_confirmed());
        // A crash after confirmation must skip all native credential reads and
        // network work. There is intentionally no remaining session locator.
        let mut confirmed = store.load().unwrap();
        tauri::async_runtime::block_on(retire_remote_credentials(&store, &mut confirmed)).unwrap();
        assert_eq!(confirmed, restored);
        assert!(canonical.get(&canonical_key).unwrap().is_some());
        assert!(pending.get(&pending_key).unwrap().is_some());
        #[cfg(target_os = "linux")]
        {
            confirmed = confirmed.into_disconnected(Utc::now());
            store.save(&confirmed).unwrap();
            crate::application::linux::disconnect::complete_local_cleanup_with_slot_cleanup(
                &store,
                &mut confirmed,
                DesktopState::finish_disconnect_cleanup,
                |slot| match slot.namespace {
                    DisconnectCredentialNamespace::Canonical => canonical.delete(&slot.account_key),
                    DisconnectCredentialNamespace::PendingCandidate => {
                        pending.delete(&slot.account_key)
                    }
                    _ => panic!("unexpected namespace"),
                },
            )
            .unwrap();
            assert!(canonical.get(&canonical_key).unwrap().is_none());
            assert!(pending.get(&pending_key).unwrap().is_none());
            assert!(!store.load().unwrap().has_pending_disconnect_cleanup());
        }
    }
}

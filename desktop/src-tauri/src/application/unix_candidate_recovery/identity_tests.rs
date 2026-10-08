use chrono::{Duration, Utc};
use shellx_drive_desktop_core::FakeCredentialStore;

use super::*;

fn record() -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        "https://drive.example.test/tenant|suffix",
        "alice|tag@example.test",
        "saved-session",
        Utc::now() + Duration::hours(1),
    )
    .unwrap()
}

#[test]
fn interrupted_pipe_path_candidates_keep_the_exact_endpoint_for_retirement_and_promotion() {
    for already_active in [false, true] {
        let saved = record();
        let identity = SessionIdentity::new(&saved.server_url, &saved.account_email);
        let slot = identity.pending_service_key(&saved.session_id).unwrap();
        let canonical = FakeCredentialStore::default();
        let pending = FakeCredentialStore::default();
        pending
            .set(&slot.account_key, "synthetic-staged-bearer")
            .unwrap();
        let mut state = if already_active {
            canonical
                .set(&identity.credential_key(), "synthetic-prior-bearer")
                .unwrap();
            DesktopState {
                active_remote_session: Some(saved.clone()),
                ..DesktopState::default()
            }
        } else {
            DesktopState {
                pending_candidate_session: Some(saved.clone()),
                ..DesktopState::default()
            }
        };
        let resolved = ordered_slots(&state, vec![slot.account_key.clone()])
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(resolved, slot);
        let mut actions = Vec::new();
        tauri::async_runtime::block_on(recover_slot(
            &mut state,
            &resolved,
            "synthetic-staged-bearer",
            RecoveryStores {
                canonical: &canonical,
                pending: &pending,
            },
            |_| Ok(()),
            |action| {
                assert_eq!(resolved.identity, identity);
                actions.push(action);
                std::future::ready(Ok(()))
            },
            || Ok(()),
        ))
        .unwrap();
        assert!(pending.get(&slot.account_key).unwrap().is_none());
        if already_active {
            assert_eq!(actions, [RemoteRecoveryAction::RetirePriorCanonical]);
            assert_eq!(state.active_remote_session, Some(saved));
            assert_eq!(
                canonical
                    .get(&identity.credential_key())
                    .unwrap()
                    .as_deref(),
                Some("synthetic-staged-bearer")
            );
        } else {
            assert_eq!(actions, [RemoteRecoveryAction::RetireCandidate]);
            assert!(state.pending_candidate_session.is_none());
        }
    }
}

#[test]
fn a_reparsed_or_unattributed_candidate_is_retained_without_effects() {
    let saved = record();
    let identity = SessionIdentity::new(&saved.server_url, &saved.account_email);
    let slot = identity.pending_service_key(&saved.session_id).unwrap();
    let reparsed = SessionIdentity::parse_pending_service_key(&slot.account_key).unwrap();
    assert_ne!(reparsed.identity, identity);
    let canonical = FakeCredentialStore::default();
    let pending = FakeCredentialStore::default();
    pending
        .set(&slot.account_key, "synthetic-staged-bearer")
        .unwrap();
    for mut state in [
        DesktopState {
            pending_candidate_session: Some(saved.clone()),
            ..DesktopState::default()
        },
        DesktopState::default(),
    ] {
        let before = state.clone();
        let result = tauri::async_runtime::block_on(recover_slot(
            &mut state,
            &reparsed,
            "synthetic-staged-bearer",
            RecoveryStores {
                canonical: &canonical,
                pending: &pending,
            },
            |_| panic!("unresolved candidate must not save"),
            |_| -> std::future::Ready<CoreResult<()>> {
                panic!("unresolved candidate must not transmit")
            },
            || panic!("unresolved candidate must not clean canonical credentials"),
        ));
        assert!(result.is_err());
        assert_eq!(state, before);
        assert!(pending.get(&slot.account_key).unwrap().is_some());
        assert!(
            remove_retired_slot(&mut state, &reparsed, &pending, |_| panic!("must not save"))
                .is_err()
        );
        assert!(pending.get(&slot.account_key).unwrap().is_some());
    }
    assert!(ordered_slots(&DesktopState::default(), vec![slot.account_key]).is_err());
}

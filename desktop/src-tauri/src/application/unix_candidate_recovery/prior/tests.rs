use std::sync::Mutex;

use chrono::{Duration, Utc};
use shellx_drive_desktop_core::{
    CredentialStore, FakeCredentialStore, StateStore, CANDIDATE_RECOVERY_PAUSED_ERROR,
};

use super::*;
use crate::application::{
    candidate_admission::prepare_candidate_state,
    unix_candidate_recovery::{persist_converged_candidate_state, recover_slot, RecoveryStores},
};

fn record(email: &str, session_id: &str) -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        "https://drive.example.test",
        email,
        session_id,
        Utc::now() + Duration::hours(1),
    )
    .unwrap()
}

#[test]
fn deleted_candidate_with_failed_final_save_recovers_after_restart_and_fresh_sign_in() {
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let old = record("person@example.test", "old");
    let identity = SessionIdentity::new(&old.server_url, &old.account_email);
    let slot = identity.pending_service_key(&old.session_id).unwrap();
    let canonical = FakeCredentialStore::default();
    let pending = FakeCredentialStore::default();
    pending.set(&slot.account_key, "old-staged-bearer").unwrap();
    let mut state = DesktopState {
        pending_candidate_session: Some(old.clone()),
        last_error: Some(CANDIDATE_RECOVERY_PAUSED_ERROR.to_string()),
        ..DesktopState::default()
    };
    store.save(&state).unwrap();
    assert!(tauri::async_runtime::block_on(recover_slot(
        &mut state,
        &slot,
        "old-staged-bearer",
        RecoveryStores {
            canonical: &canonical,
            pending: &pending
        },
        |_| Err(recovery_error()),
        |_| async { Ok(()) },
        || Ok(()),
    ))
    .is_err());
    assert!(pending.get(&slot.account_key).unwrap().is_none());
    let restarted = store.load().unwrap();
    assert_eq!(restarted.pending_candidate_session, Some(old.clone()));
    assert!(state.pending_candidate_session.is_some());
    assert!(
        persist_converged_candidate_state(&mut state, Vec::new(), |_| {
            panic!("missing staged bytes do not prove durable retirement")
        })
        .is_err()
    );

    let fresh = record("person@example.test", "fresh");
    let mut candidate = prepare_candidate_state(&restarted, &fresh, Utc::now()).unwrap();
    store.save(&candidate).unwrap();
    let fresh_slot = identity.pending_service_key(&fresh.session_id).unwrap();
    pending
        .set(&fresh_slot.account_key, "fresh-staged-bearer")
        .unwrap();
    let retired = Mutex::new(Vec::new());
    tauri::async_runtime::block_on(retire_prior_candidate_sessions(
        &mut candidate,
        &pending,
        &identity,
        &fresh,
        |image| store.save(image),
        |exact| {
            retired.lock().unwrap().push(exact.session_id);
            async { Ok(()) }
        },
    ))
    .unwrap();
    assert_eq!(*retired.lock().unwrap(), ["old"]);
    assert!(store.load().unwrap().pending_remote_revocations.is_empty());
    assert_eq!(candidate.pending_candidate_session, Some(fresh.clone()));
    assert_eq!(
        pending.get(&fresh_slot.account_key).unwrap().as_deref(),
        Some("fresh-staged-bearer")
    );
    assert!(canonical.get(&identity.credential_key()).unwrap().is_none());

    canonical
        .set(&identity.credential_key(), "fresh-staged-bearer")
        .unwrap();
    pending.delete(&fresh_slot.account_key).unwrap();
    candidate.publish_active_remote_session(fresh.clone());
    persist_converged_candidate_state(&mut candidate, Vec::new(), |image| store.save(image))
        .unwrap();
    let complete = store.load().unwrap();
    assert_eq!(complete.active_remote_session, Some(fresh));
    assert!(complete.pending_candidate_session.is_none());
    assert!(complete.last_error.is_none());
}

#[test]
fn fresh_sign_in_retires_only_owned_exact_same_identity_sessions() {
    let fresh = record("person@example.test", "fresh");
    let owned = record("person@example.test", "owned");
    let foreign = record("other@example.test", "foreign");
    let identity = SessionIdentity::new(&fresh.server_url, &fresh.account_email);
    let owned_slot = identity.pending_service_key(&owned.session_id).unwrap();
    let unowned_slot = identity
        .pending_service_key("unowned-same-account")
        .unwrap();
    let foreign_slot = SessionIdentity::new(&foreign.server_url, &foreign.account_email)
        .pending_service_key(&foreign.session_id)
        .unwrap();
    let pending = FakeCredentialStore::default();
    for slot in [&owned_slot, &unowned_slot, &foreign_slot] {
        pending.set(&slot.account_key, "retained-bearer").unwrap();
    }
    let mut state = DesktopState {
        pending_candidate_session: Some(fresh.clone()),
        pending_remote_revocations: vec![owned, foreign.clone()],
        ..DesktopState::default()
    };
    let retired = Mutex::new(Vec::new());
    tauri::async_runtime::block_on(retire_prior_candidate_sessions(
        &mut state,
        &pending,
        &identity,
        &fresh,
        |_| Ok(()),
        |exact| {
            retired.lock().unwrap().push(exact.session_id);
            async { Ok(()) }
        },
    ))
    .unwrap();
    assert_eq!(*retired.lock().unwrap(), ["owned"]);
    assert!(pending.get(&owned_slot.account_key).unwrap().is_none());
    assert_eq!(
        pending.get(&unowned_slot.account_key).unwrap().as_deref(),
        Some("retained-bearer")
    );
    assert_eq!(
        pending.get(&foreign_slot.account_key).unwrap().as_deref(),
        Some("retained-bearer")
    );
    assert_eq!(state.pending_remote_revocations, [foreign]);
    assert_eq!(state.pending_candidate_session, Some(fresh));
}

struct RetainedPendingStore(FakeCredentialStore);

impl CredentialStore for RetainedPendingStore {
    fn get(&self, key: &str) -> CoreResult<Option<String>> {
        self.0.get(key)
    }
    fn set(&self, _: &str, _: &str) -> CoreResult<()> {
        panic!("retirement must not stage a new bearer")
    }
    fn delete(&self, _: &str) -> CoreResult<()> {
        Err(recovery_error())
    }
}

#[test]
fn failed_local_delete_keeps_exact_restart_ownership_until_successful_retry() {
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let fresh = record("person@example.test", "fresh");
    let old = record("person@example.test", "old");
    let identity = SessionIdentity::new(&old.server_url, &old.account_email);
    let slot = identity.pending_service_key(&old.session_id).unwrap();
    let pending = RetainedPendingStore(FakeCredentialStore::default());
    pending
        .0
        .set(&slot.account_key, "retained-old-bearer")
        .unwrap();
    let mut state = DesktopState {
        pending_candidate_session: Some(fresh.clone()),
        pending_remote_revocations: vec![old.clone()],
        ..DesktopState::default()
    };
    store.save(&state).unwrap();
    assert!(
        tauri::async_runtime::block_on(retire_prior_candidate_sessions(
            &mut state,
            &pending,
            &identity,
            &fresh,
            |image| store.save(image),
            |_| async { Ok(()) },
        ))
        .is_err()
    );
    let mut restarted = store.load().unwrap();
    assert_eq!(restarted.pending_candidate_session, Some(fresh.clone()));
    assert_eq!(restarted.pending_remote_revocations, [old]);
    assert_eq!(
        pending.0.get(&slot.account_key).unwrap().as_deref(),
        Some("retained-old-bearer")
    );

    tauri::async_runtime::block_on(retire_prior_candidate_sessions(
        &mut restarted,
        &pending.0,
        &identity,
        &fresh,
        |image| store.save(image),
        |_| async { Ok(()) },
    ))
    .unwrap();
    assert!(pending.0.get(&slot.account_key).unwrap().is_none());
    let complete = store.load().unwrap();
    assert!(complete.pending_remote_revocations.is_empty());
    assert_eq!(complete.pending_candidate_session, Some(fresh));
}

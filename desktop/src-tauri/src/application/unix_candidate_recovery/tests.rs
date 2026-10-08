use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

use chrono::{Duration, Utc};
use shellx_drive_desktop_core::FakeCredentialStore;

use super::*;

const BEARER: &str = "test-only-staged-bearer";

fn record(session_id: &str) -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        "https://drive.example.test",
        "person@example.test",
        session_id,
        Utc::now() + Duration::hours(1),
    )
    .unwrap()
}

struct Harness {
    canonical: FakeCredentialStore,
    pending: FakeCredentialStore,
    slot: ServiceCredentialKey,
    events: Mutex<Vec<&'static str>>,
    persisted: Mutex<Option<DesktopState>>,
}

impl Harness {
    fn new(session_id: &str) -> Self {
        let slot = SessionIdentity::new("https://drive.example.test", "person@example.test")
            .pending_service_key(session_id)
            .unwrap();
        let pending = FakeCredentialStore::default();
        pending.set(&slot.account_key, BEARER).unwrap();
        Self {
            canonical: FakeCredentialStore::default(),
            pending,
            slot,
            events: Mutex::new(Vec::new()),
            persisted: Mutex::new(None),
        }
    }

    fn recover(
        &self,
        state: &mut DesktopState,
        canonical: &dyn CredentialStore,
        fail_save: bool,
        fail_remote: bool,
        fail_cleanup: bool,
    ) -> CoreResult<()> {
        self.recover_with_stores(
            state,
            canonical,
            &self.pending,
            fail_save,
            fail_remote,
            fail_cleanup,
        )
    }

    fn recover_with_stores(
        &self,
        state: &mut DesktopState,
        canonical: &dyn CredentialStore,
        pending: &dyn CredentialStore,
        fail_save: bool,
        fail_remote: bool,
        fail_cleanup: bool,
    ) -> CoreResult<()> {
        tauri::async_runtime::block_on(recover_slot(
            state,
            &self.slot,
            BEARER,
            RecoveryStores { canonical, pending },
            |image| {
                self.events.lock().unwrap().push("save");
                if fail_save {
                    return Err(recovery_error());
                }
                *self.persisted.lock().unwrap() = Some(image.clone());
                Ok(())
            },
            |action| async move {
                self.events.lock().unwrap().push(match action {
                    RemoteRecoveryAction::RetireCandidate => "retire candidate",
                    RemoteRecoveryAction::RetirePriorCanonical => "retire prior canonical",
                });
                if fail_remote {
                    Err(recovery_error())
                } else {
                    Ok(())
                }
            },
            || {
                self.events.lock().unwrap().push("cleanup canonical");
                if fail_cleanup {
                    Err(recovery_error())
                } else {
                    Ok(())
                }
            },
        ))
    }

    fn staged(&self) -> Option<String> {
        self.pending.get(&self.slot.account_key).unwrap()
    }
}

#[test]
fn canceled_pending_only_candidate_is_retired_without_replacing_active_session() {
    let harness = Harness::new("canceled");
    let active = record("previous");
    harness
        .canonical
        .set(&harness.slot.identity.credential_key(), "previous-bearer")
        .unwrap();
    let mut state = DesktopState {
        active_remote_session: Some(active.clone()),
        pending_candidate_session: Some(record("canceled")),
        ..DesktopState::default()
    };
    harness
        .recover(&mut state, &harness.canonical, false, false, false)
        .unwrap();
    assert_eq!(state.active_remote_session, Some(active));
    assert!(state.pending_candidate_session.is_none());
    assert!(harness.staged().is_none());
    assert_eq!(
        harness
            .canonical
            .get(&harness.slot.identity.credential_key())
            .unwrap()
            .as_deref(),
        Some("previous-bearer")
    );
    assert_eq!(
        *harness.events.lock().unwrap(),
        ["retire candidate", "save"]
    );
    assert!(harness
        .persisted
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .pending_candidate_session
        .is_none());
}

#[test]
fn disconnected_canceled_candidate_is_retired_and_never_restores_an_active_session() {
    let harness = Harness::new("canceled");
    let mut state = DesktopState {
        pending_candidate_session: Some(record("canceled")),
        ..DesktopState::default()
    };
    harness
        .recover(&mut state, &harness.canonical, false, false, false)
        .unwrap();
    assert!(state.active_remote_session.is_none());
    assert!(state.pending_candidate_session.is_none());
    assert!(harness
        .canonical
        .get(&harness.slot.identity.credential_key())
        .unwrap()
        .is_none());
    assert!(harness.staged().is_none());
    assert_eq!(
        *harness.events.lock().unwrap(),
        ["retire candidate", "save"]
    );
}

#[test]
fn failed_remote_retirement_keeps_canceled_locator_and_staged_bearer() {
    let harness = Harness::new("canceled");
    let canceled = record("canceled");
    let mut state = DesktopState {
        pending_candidate_session: Some(canceled.clone()),
        ..DesktopState::default()
    };
    assert!(harness
        .recover(&mut state, &harness.canonical, false, true, false)
        .is_err());
    assert_eq!(state.pending_candidate_session, Some(canceled));
    assert!(state.active_remote_session.is_none());
    assert_eq!(harness.staged().as_deref(), Some(BEARER));
    assert_eq!(*harness.events.lock().unwrap(), ["retire candidate"]);
}

#[test]
fn failed_locator_save_keeps_staged_bearer_after_confirmed_retirement() {
    let harness = Harness::new("canceled");
    let canceled = record("canceled");
    let mut state = DesktopState {
        pending_candidate_session: Some(canceled.clone()),
        ..DesktopState::default()
    };
    assert!(harness
        .recover(&mut state, &harness.canonical, true, false, false)
        .is_err());
    assert_eq!(state.pending_candidate_session, Some(canceled));
    assert_eq!(harness.staged().as_deref(), Some(BEARER));
    assert_eq!(
        *harness.events.lock().unwrap(),
        ["retire candidate", "save"]
    );
    assert!(harness.persisted.lock().unwrap().is_none());
}

struct UnavailableStore;

impl CredentialStore for UnavailableStore {
    fn get(&self, _: &str) -> CoreResult<Option<String>> {
        Err(recovery_error())
    }
    fn set(&self, _: &str, _: &str) -> CoreResult<()> {
        panic!("uncertain read must not write")
    }
    fn delete(&self, _: &str) -> CoreResult<()> {
        panic!("uncertain read must not delete")
    }
}

#[test]
fn unavailable_canonical_provider_retains_candidate_without_remote_or_local_effects() {
    let harness = Harness::new("canceled");
    let canceled = record("canceled");
    let mut state = DesktopState {
        pending_candidate_session: Some(canceled.clone()),
        ..DesktopState::default()
    };
    assert!(harness
        .recover(&mut state, &UnavailableStore, false, false, false)
        .is_err());
    assert_eq!(state.pending_candidate_session, Some(canceled));
    assert_eq!(harness.staged().as_deref(), Some(BEARER));
    assert!(harness.events.lock().unwrap().is_empty());
}

#[test]
fn matching_canonical_candidate_is_saved_as_active_before_staged_cleanup() {
    let harness = Harness::new("published");
    let published = record("published");
    harness
        .canonical
        .set(&harness.slot.identity.credential_key(), BEARER)
        .unwrap();
    let mut state = DesktopState {
        pending_candidate_session: Some(published.clone()),
        ..DesktopState::default()
    };
    harness
        .recover(&mut state, &harness.canonical, false, false, false)
        .unwrap();
    assert_eq!(state.active_remote_session, Some(published.clone()));
    assert!(state.pending_candidate_session.is_none());
    assert!(harness.staged().is_none());
    assert_eq!(
        harness
            .persisted
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .active_remote_session,
        Some(published)
    );
    assert_eq!(
        *harness.events.lock().unwrap(),
        ["retire prior canonical", "save", "cleanup canonical"]
    );
}

#[test]
fn durable_active_candidate_completes_canonical_write_and_preserves_newer_pending() {
    let harness = Harness::new("active");
    let active = record("active");
    let newer = record("newer");
    harness
        .canonical
        .set(&harness.slot.identity.credential_key(), "old-canonical")
        .unwrap();
    let mut state = DesktopState {
        active_remote_session: Some(active.clone()),
        pending_candidate_session: Some(newer.clone()),
        ..DesktopState::default()
    };
    harness
        .recover(&mut state, &harness.canonical, false, false, false)
        .unwrap();
    assert_eq!(state.active_remote_session, Some(active));
    assert_eq!(state.pending_candidate_session, Some(newer));
    assert_eq!(
        harness
            .canonical
            .get(&harness.slot.identity.credential_key())
            .unwrap()
            .as_deref(),
        Some(BEARER)
    );
    assert!(harness.staged().is_none());
    assert_eq!(
        *harness.events.lock().unwrap(),
        ["retire prior canonical", "cleanup canonical"]
    );
}

#[test]
fn superseded_canonical_matching_slot_cannot_replace_authoritative_candidate() {
    let harness = Harness::new("stale");
    let fresh = record("fresh");
    harness
        .canonical
        .set(&harness.slot.identity.credential_key(), BEARER)
        .unwrap();
    let mut state = DesktopState {
        pending_candidate_session: Some(fresh.clone()),
        ..DesktopState::default()
    };
    assert!(harness
        .recover(&mut state, &harness.canonical, false, false, false)
        .is_err());
    assert_eq!(state.pending_candidate_session, Some(fresh));
    assert!(state.active_remote_session.is_none());
    assert_eq!(harness.staged().as_deref(), Some(BEARER));
    assert!(harness.events.lock().unwrap().is_empty());
}

#[test]
fn cleanup_failure_keeps_staged_credential_with_saved_active_locator() {
    let harness = Harness::new("published");
    let published = record("published");
    harness
        .canonical
        .set(&harness.slot.identity.credential_key(), BEARER)
        .unwrap();
    let mut state = DesktopState {
        pending_candidate_session: Some(published.clone()),
        ..DesktopState::default()
    };
    assert!(harness
        .recover(&mut state, &harness.canonical, false, false, true)
        .is_err());
    assert_eq!(state.active_remote_session, Some(published.clone()));
    assert_eq!(
        harness
            .persisted
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .active_remote_session,
        Some(published)
    );
    assert_eq!(harness.staged().as_deref(), Some(BEARER));
}

#[test]
fn staged_slots_prioritize_exact_authoritative_candidate_and_reject_malformed_keys() {
    let identity = SessionIdentity::new("https://drive.example.test", "person@example.test");
    let state = DesktopState {
        pending_candidate_session: Some(record("z_fresh")),
        ..DesktopState::default()
    };
    let fresh = identity.pending_service_key("z_fresh").unwrap();
    let stale = identity.pending_service_key("a_stale").unwrap();
    let slots = ordered_slots(
        &state,
        vec![stale.account_key.clone(), fresh.account_key.clone()],
    )
    .unwrap();
    assert_eq!(slots, [fresh, stale]);
    assert!(ordered_slots(&state, vec!["not-an-admitted-slot".to_string()]).is_err());
}

struct FailedCanonicalWrite {
    values: FakeCredentialStore,
    attempted: AtomicBool,
    uncertain_readback: bool,
}

impl CredentialStore for FailedCanonicalWrite {
    fn get(&self, key: &str) -> CoreResult<Option<String>> {
        if self.uncertain_readback && self.attempted.load(Ordering::Acquire) {
            Err(recovery_error())
        } else {
            self.values.get(key)
        }
    }
    fn set(&self, key: &str, value: &str) -> CoreResult<()> {
        self.values.set(key, value)?;
        self.attempted.store(true, Ordering::Release);
        Err(recovery_error())
    }
    fn delete(&self, _: &str) -> CoreResult<()> {
        panic!("publication must not delete the canonical destination")
    }
}

#[test]
fn canonical_write_error_uses_exact_readback_and_retains_stage_on_uncertainty() {
    for uncertain_readback in [false, true] {
        let harness = Harness::new("active");
        let active = record("active");
        let newer = record("newer");
        let canonical = FailedCanonicalWrite {
            values: FakeCredentialStore::default(),
            attempted: AtomicBool::new(false),
            uncertain_readback,
        };
        canonical
            .values
            .set(&harness.slot.identity.credential_key(), "old-canonical")
            .unwrap();
        let mut state = DesktopState {
            active_remote_session: Some(active.clone()),
            pending_candidate_session: Some(newer.clone()),
            ..DesktopState::default()
        };
        let result = harness.recover(&mut state, &canonical, false, false, false);
        assert_eq!(result.is_err(), uncertain_readback);
        assert!(canonical.attempted.load(Ordering::Acquire));
        assert_eq!(
            canonical
                .values
                .get(&harness.slot.identity.credential_key())
                .unwrap()
                .as_deref(),
            Some(BEARER)
        );
        assert_eq!(state.active_remote_session, Some(active));
        assert_eq!(state.pending_candidate_session, Some(newer));
        if uncertain_readback {
            assert_eq!(harness.staged().as_deref(), Some(BEARER));
            assert_eq!(*harness.events.lock().unwrap(), ["retire prior canonical"]);
        } else {
            assert!(harness.staged().is_none());
            assert_eq!(
                *harness.events.lock().unwrap(),
                ["retire prior canonical", "cleanup canonical"]
            );
        }
    }
}

struct FailedStagedDelete {
    values: FakeCredentialStore,
    attempted: AtomicBool,
    uncertain_readback: bool,
}

impl CredentialStore for FailedStagedDelete {
    fn get(&self, key: &str) -> CoreResult<Option<String>> {
        if self.uncertain_readback && self.attempted.load(Ordering::Acquire) {
            Err(recovery_error())
        } else {
            self.values.get(key)
        }
    }
    fn set(&self, _: &str, _: &str) -> CoreResult<()> {
        panic!("retirement must not stage a new credential")
    }
    fn delete(&self, _: &str) -> CoreResult<()> {
        self.attempted.store(true, Ordering::Release);
        Err(recovery_error())
    }
}

#[test]
fn failed_or_uncertain_staged_deletion_keeps_bearer_after_durable_retirement() {
    for uncertain_readback in [false, true] {
        let harness = Harness::new("canceled");
        let pending = FailedStagedDelete {
            values: FakeCredentialStore::default(),
            attempted: AtomicBool::new(false),
            uncertain_readback,
        };
        pending
            .values
            .set(&harness.slot.account_key, BEARER)
            .unwrap();
        let mut state = DesktopState {
            pending_candidate_session: Some(record("canceled")),
            ..DesktopState::default()
        };
        assert!(harness
            .recover_with_stores(
                &mut state,
                &harness.canonical,
                &pending,
                false,
                false,
                false
            )
            .is_err());
        assert!(pending.attempted.load(Ordering::Acquire));
        assert!(state.active_remote_session.is_none());
        assert!(state.pending_candidate_session.is_none());
        assert_eq!(
            pending
                .values
                .get(&harness.slot.account_key)
                .unwrap()
                .as_deref(),
            Some(BEARER)
        );
        assert!(harness
            .persisted
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .pending_candidate_session
            .is_none());
        assert_eq!(
            *harness.events.lock().unwrap(),
            ["retire candidate", "save"]
        );
    }
}

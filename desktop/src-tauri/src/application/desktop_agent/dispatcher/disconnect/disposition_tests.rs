use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use chrono::{Duration, Utc};
use shellx_drive_desktop_core::{
    desktop_agent_disconnect_credential_key, CredentialStore, DesktopAgentDeviceAssertion,
    DesktopAgentDisconnectContinuation, DesktopAgentDisconnectPhase, DesktopAgentObservedStatus,
    DesktopError, DesktopState, DisconnectCleanupIntent, FakeCredentialStore, RemoteSessionRecord,
    Result as CoreResult, StateStore,
};

use super::super::{
    complete_after_retirement, retire_remote, retirement_retry_is_locally_admitted,
};
use super::{read_capability, Runtime};
use crate::platform::PlatformServices;

const CAPABILITY: &str = "sxd_disconnect_fixture";
const INVALID_CAPABILITY: &str = "not-a-disconnect-capability";

#[derive(Default)]
struct FlakyCredentialStore {
    values: FakeCredentialStore,
    failed_reads_remaining: Mutex<usize>,
}

impl FlakyCredentialStore {
    fn fail_next_read(&self) {
        *self
            .failed_reads_remaining
            .lock()
            .expect("fixture failure lock") = 1;
    }
}

impl CredentialStore for FlakyCredentialStore {
    fn get(&self, account_key: &str) -> CoreResult<Option<String>> {
        let mut failed_reads_remaining = self
            .failed_reads_remaining
            .lock()
            .expect("fixture failure lock");
        if *failed_reads_remaining > 0 {
            *failed_reads_remaining -= 1;
            return Err(DesktopError::Credential(
                "fixture transient credential provider failure".to_string(),
            ));
        }
        drop(failed_reads_remaining);
        self.values.get(account_key)
    }

    fn set(&self, account_key: &str, bearer_token: &str) -> CoreResult<()> {
        self.values.set(account_key, bearer_token)
    }

    fn delete(&self, account_key: &str) -> CoreResult<()> {
        self.values.delete(account_key)
    }
}

struct TestPlatform {
    credentials: Arc<FlakyCredentialStore>,
}

impl PlatformServices for TestPlatform {
    fn credentials(&self) -> &dyn CredentialStore {
        self.credentials.as_ref()
    }

    fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
        self.credentials.as_ref()
    }

    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
        self.credentials.as_ref()
    }

    fn set_launch_at_login(&self, _: bool) -> CoreResult<()> {
        Ok(())
    }

    fn open_local_root(&self, _: &Path) -> CoreResult<()> {
        Ok(())
    }

    fn open_drive_url(&self, _: &str) -> CoreResult<()> {
        Ok(())
    }
}

fn retiring_continuation() -> DesktopAgentDisconnectContinuation {
    DesktopAgentDisconnectContinuation {
        canonical_server_origin: "https://drive.example.test".to_string(),
        command_id: "command_1".to_string(),
        lease_id: "lease_1".to_string(),
        retirement_expires_at: Some(Utc::now() + Duration::seconds(45)),
        completion_expires_at: Utc::now() + Duration::minutes(10),
        completion_event_sequence: 3,
        phase: DesktopAgentDisconnectPhase::RetiringRemote,
        retire_assertion: Some(DesktopAgentDeviceAssertion {
            app_version: "1.0.0".to_string(),
            pair_fingerprint: "a".repeat(64),
            status: DesktopAgentObservedStatus::Ready,
            pending_disconnect_cleanup: true,
            candidate_recovery: false,
            last_terminal_command_id: None,
        }),
        bound_owner_session: Some(
            RemoteSessionRecord::new(
                "https://drive.example.test",
                "owner@example.test",
                "session_1",
                Utc::now() + Duration::hours(1),
            )
            .expect("valid remote-session fixture"),
        ),
        terminal_receipt: None,
        blocked_reason: None,
    }
}

fn retiring_state() -> DesktopState {
    let mut state = DesktopState::default();
    state
        .begin_disconnect_cleanup(
            DisconnectCleanupIntent::for_disconnect(None, Vec::new())
                .expect("valid cleanup fixture"),
        )
        .expect("begin cleanup");
    state
        .desktop_agent_control
        .enroll("device_1".to_string(), None, "a".repeat(64))
        .expect("enroll fixture device");
    state
        .begin_desktop_agent_disconnect(retiring_continuation())
        .expect("begin retiring continuation");
    state
}

fn reporting_state() -> DesktopState {
    let mut state = retiring_state();
    state
        .mark_desktop_agent_disconnect_retired()
        .expect("record remote retirement");
    state = state.into_disconnected(Utc::now());
    state
        .pending_disconnect_cleanup_mut()
        .expect("cleanup remains pending")
        .confirm_remote_retirement();
    state.finish_disconnect_cleanup().expect("finish cleanup");
    state
        .mark_desktop_agent_disconnect_reporting()
        .expect("begin completion reporting");
    state
}

fn runtime_for(
    state: DesktopState,
    credentials: Arc<FlakyCredentialStore>,
) -> (Runtime, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform { credentials }),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    runtime.save().expect("persist fixture state");
    (runtime, directory)
}

fn pending_continuation(runtime: &Runtime) -> DesktopAgentDisconnectContinuation {
    runtime
        .coordinator
        .snapshot()
        .pending_desktop_agent_disconnect()
        .cloned()
        .expect("pending Disconnect continuation")
}

fn credential_key(continuation: &DesktopAgentDisconnectContinuation) -> String {
    desktop_agent_disconnect_credential_key(
        &continuation.canonical_server_origin,
        &continuation.command_id,
    )
}

fn store_capability(
    credentials: &FlakyCredentialStore,
    continuation: &DesktopAgentDisconnectContinuation,
) {
    credentials
        .set(&credential_key(continuation), CAPABILITY)
        .expect("store fixture capability");
}

fn assert_capability_available(
    runtime: &Runtime,
    continuation: &DesktopAgentDisconnectContinuation,
) {
    assert_eq!(
        read_capability(runtime, continuation).expect("credential provider must succeed"),
        Some(CAPABILITY.to_string())
    );
}

fn assert_continuation_is_retained(runtime: &Runtime, phase: DesktopAgentDisconnectPhase) {
    for state in [
        runtime.coordinator.snapshot(),
        runtime.store.load().expect("load persisted fixture state"),
    ] {
        assert_eq!(
            state
                .pending_desktop_agent_disconnect()
                .expect("continuation must remain pending")
                .phase,
            phase
        );
        assert!(state.unconfirmed_desktop_agent_disconnect.is_none());
    }
}

#[test]
fn unavailable_or_malformed_capability_is_not_admitted() {
    let credentials = Arc::new(FlakyCredentialStore::default());
    let (runtime, _directory) = runtime_for(retiring_state(), Arc::clone(&credentials));
    let continuation = pending_continuation(&runtime);

    assert_eq!(read_capability(&runtime, &continuation).unwrap(), None);
    credentials
        .set(&credential_key(&continuation), INVALID_CAPABILITY)
        .expect("store malformed fixture capability");
    assert_eq!(read_capability(&runtime, &continuation).unwrap(), None);
}

#[test]
fn retirement_admission_retries_after_a_transient_credential_provider_failure() {
    let state = retiring_state();
    let continuation = state
        .pending_desktop_agent_disconnect()
        .cloned()
        .expect("retiring continuation");
    let credentials = Arc::new(FlakyCredentialStore::default());
    store_capability(&credentials, &continuation);
    let (runtime, _directory) = runtime_for(state, Arc::clone(&credentials));

    assert_capability_available(&runtime, &continuation);
    credentials.fail_next_read();
    let error = retirement_retry_is_locally_admitted(&runtime, &continuation)
        .expect_err("provider failure must propagate");
    assert!(matches!(error, DesktopError::Credential(_)));
    assert_continuation_is_retained(&runtime, DesktopAgentDisconnectPhase::RetiringRemote);
    assert_capability_available(&runtime, &continuation);
    assert!(retirement_retry_is_locally_admitted(&runtime, &continuation).unwrap());
}

#[test]
fn remote_retirement_retries_after_a_transient_credential_provider_failure() {
    let state = retiring_state();
    let continuation = state
        .pending_desktop_agent_disconnect()
        .cloned()
        .expect("retiring continuation");
    let credentials = Arc::new(FlakyCredentialStore::default());
    store_capability(&credentials, &continuation);
    let (runtime, _directory) = runtime_for(state, Arc::clone(&credentials));

    assert_capability_available(&runtime, &continuation);
    credentials.fail_next_read();
    let error = tauri::async_runtime::block_on(retire_remote(&runtime))
        .err()
        .expect("provider failure must propagate before retirement RPC");
    assert!(matches!(error, DesktopError::Credential(_)));
    assert_continuation_is_retained(&runtime, DesktopAgentDisconnectPhase::RetiringRemote);
    assert_capability_available(&runtime, &continuation);
}

#[test]
fn completion_retries_after_a_transient_credential_provider_failure() {
    let state = reporting_state();
    let continuation = state
        .pending_desktop_agent_disconnect()
        .cloned()
        .expect("reporting continuation");
    let credentials = Arc::new(FlakyCredentialStore::default());
    store_capability(&credentials, &continuation);
    let (runtime, _directory) = runtime_for(state, Arc::clone(&credentials));

    assert_capability_available(&runtime, &continuation);
    credentials.fail_next_read();
    let error = tauri::async_runtime::block_on(complete_after_retirement(&runtime))
        .err()
        .expect("provider failure must propagate before completion RPC");
    assert!(matches!(error, DesktopError::Credential(_)));
    assert_continuation_is_retained(&runtime, DesktopAgentDisconnectPhase::Reporting);
    assert_capability_available(&runtime, &continuation);
}

use chrono::{Duration, Utc};
use shellx_drive_desktop_core::{
    desktop_agent_enrollment_fingerprint, CredentialStore, DesktopAgentCommandKind, DesktopState,
    DriveHttpClient, FakeCredentialStore, StateStore, SyncPair,
};

use super::{execute, CommandLease, Runtime};
use crate::application::runtime::tests::TestPlatform;

const SERVER: &str = "https://drive.example.test";
const EMAIL: &str = "person@example.test";
const BEARER: &str = concat!(
    "sso.v1.eyJqdGkiOiJzZXNzaW9uLTEiLCJlbWFpbCI6InBlcnNvbkBleGFtcGxlLnRlc3QiLC",
    "Jpc3N1ZXIiOiJsb2NhbC1wYXNzd29yZCIsImV4cGlyZXNfYXQiOjQxMDI0NDQ4MDAsImFk",
    "bWluIjpmYWxzZX0.fixture-signature"
);

fn state(root: &std::path::Path) -> DesktopState {
    let mut state = DesktopState {
        pair: Some(SyncPair {
            server_url: SERVER.to_string(),
            account_email: EMAIL.to_string(),
            workspace_id: "workspace-1".to_string(),
            workspace_name: "Workspace".to_string(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: root.join("Drive"),
            local_root_identity: None,
        }),
        ..DesktopState::default()
    };
    state
        .desktop_agent_control
        .enroll(
            "device-1".to_string(),
            None,
            desktop_agent_enrollment_fingerprint(SERVER, EMAIL),
        )
        .unwrap();
    state
        .desktop_agent_control
        .record_lease(
            "command-1".to_string(),
            "lease-1".to_string(),
            DesktopAgentCommandKind::Disconnect,
            Utc::now(),
        )
        .unwrap();
    state
}

fn runtime(root: &std::path::Path, state_path: std::path::PathBuf, with_session: bool) -> Runtime {
    let credentials = FakeCredentialStore::default();
    if with_session {
        credentials
            .set(&Runtime::credential_key(SERVER, EMAIL), BEARER)
            .unwrap();
    }
    Runtime::from_loaded_state(
        Box::new(TestPlatform(credentials)),
        StateStore::new(state_path),
        state(root),
    )
}

fn lease<'a>(client: &'a DriveHttpClient, expires_at: chrono::DateTime<Utc>) -> CommandLease<'a> {
    CommandLease {
        client,
        device_credential: "sxd_device_fixture",
        command_id: "command-1",
        lease_id: "lease-1",
        expires_at,
        disconnect_completion_capability: Some("sxd_disconnect_fixture"),
        disconnect_completion_expires_at: Some(Utc::now() + Duration::minutes(10)),
    }
}

fn assert_no_partial_admission(runtime: &Runtime) {
    let state = runtime.coordinator.snapshot();
    assert!(!state.has_pending_disconnect_cleanup());
    assert!(state.pending_desktop_agent_disconnect().is_none());
}

#[test]
fn expired_claim_does_not_publish_bare_cleanup_intent() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(directory.path(), directory.path().join("state.json"), true);
    let run = runtime.coordinator.begin_run().unwrap();
    let client = DriveHttpClient::new(SERVER).unwrap();
    let result = tauri::async_runtime::block_on(execute(
        &runtime,
        &lease(&client, Utc::now() - Duration::seconds(1)),
    ));
    assert!(result.is_err());
    assert!(run.ensure_not_cancelled().is_ok());
    assert_no_partial_admission(&runtime);
    assert!(!runtime.coordinator.view_snapshot().disconnect_requested);
}

#[test]
fn missing_bound_session_does_not_publish_bare_cleanup_intent() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime(directory.path(), directory.path().join("state.json"), false);
    let run = runtime.coordinator.begin_run().unwrap();
    let client = DriveHttpClient::new(SERVER).unwrap();
    let result = tauri::async_runtime::block_on(execute(
        &runtime,
        &lease(&client, Utc::now() + Duration::seconds(45)),
    ));
    assert!(result.is_err());
    assert!(run.ensure_not_cancelled().is_ok());
    assert_no_partial_admission(&runtime);
    assert!(!runtime.coordinator.view_snapshot().disconnect_requested);
}

#[test]
fn failed_atomic_continuation_save_publishes_neither_journal_half() {
    let directory = tempfile::tempdir().unwrap();
    let invalid_parent = directory.path().join("not-a-directory");
    std::fs::write(&invalid_parent, b"fixture").unwrap();
    let runtime = runtime(directory.path(), invalid_parent.join("state.json"), true);
    let client = DriveHttpClient::new(SERVER).unwrap();
    let result = tauri::async_runtime::block_on(execute(
        &runtime,
        &lease(&client, Utc::now() + Duration::seconds(45)),
    ));
    assert!(result.is_err());
    assert_no_partial_admission(&runtime);
}

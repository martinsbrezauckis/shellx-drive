use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(not(target_os = "linux"))]
use shellx_drive_desktop_core::DriveHttpClient;
use shellx_drive_desktop_core::{
    CredentialStore, DesktopError, DesktopState, FakeCredentialStore, Result as CoreResult,
    StateStore, SyncPair, SyncStatus,
};

#[cfg(target_os = "linux")]
use super::failure::is_sync_admission_error;
use super::failure::{persist_terminal_failure, TerminalFailure};
use crate::{application::Runtime, platform::PlatformServices};

struct TestPlatform(Arc<FakeCredentialStore>);

impl PlatformServices for TestPlatform {
    fn credentials(&self) -> &dyn CredentialStore {
        self.0.as_ref()
    }

    fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
        self.0.as_ref()
    }

    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
        self.0.as_ref()
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

fn pair() -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: "selected".to_string(),
        workspace_name: "selected".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: PathBuf::from("/tmp/shellx-drive-terminal-selected"),
        local_root_identity: None,
    }
}

fn runtime(
    state_path: PathBuf,
    credentials: Arc<FakeCredentialStore>,
    server_url: &str,
) -> (Runtime, SyncPair) {
    let mut pair = pair();
    pair.server_url = server_url.to_string();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(credentials)),
        StateStore::new(state_path),
        DesktopState {
            pair: Some(pair.clone()),
            last_successful_sync: Some(
                "2026-09-09T11:24:02Z"
                    .parse()
                    .expect("fixed successful-sync timestamp"),
            ),
            ..DesktopState::default()
        },
    );
    (runtime, pair)
}

#[test]
fn refused_sync_transport_persists_offline_without_replacing_success_baseline() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let state_path = directory.path().join("state.json");
    let credentials = Arc::new(FakeCredentialStore::default());
    let (runtime, pair) = runtime(
        state_path.clone(),
        Arc::clone(&credentials),
        if cfg!(target_os = "linux") {
            "https://127.0.0.1:0"
        } else {
            "https://drive.example.test"
        },
    );
    credentials
        .set(
            &Runtime::credential_key(&pair.server_url, &pair.account_email),
            "test-bearer",
        )
        .expect("test credential");
    let error = {
        #[cfg(target_os = "linux")]
        {
            tauri::async_runtime::block_on(
                crate::application::linux::roots::refresh_authorized_roots(&runtime),
            )
            .expect_err("closed loopback port must refuse root discovery")
        }
        #[cfg(not(target_os = "linux"))]
        {
            tauri::async_runtime::block_on(
                DriveHttpClient::new("https://127.0.0.1:0")
                    .expect("valid loopback origin")
                    .validate_server(),
            )
            .expect_err("closed loopback port must refuse the transport")
        }
    };
    assert!(matches!(&error, DesktopError::Http(_)));

    assert!(matches!(
        persist_terminal_failure(&runtime, error).expect("offline state is persistable"),
        TerminalFailure::Offline
    ));
    assert_eq!(runtime.status(), SyncStatus::Offline);
    let saved = StateStore::new(&state_path)
        .load()
        .expect("persisted desktop state");
    assert_eq!(
        saved.last_successful_sync,
        Some("2026-09-09T11:24:02Z".parse().unwrap())
    );
    assert!(saved.last_error.is_none());
    assert_eq!(
        saved.activity.last().map(|entry| entry.result.as_str()),
        Some("Offline; retry remains available.")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn root_discovery_admission_errors_leave_reconnect_ready_without_a_stale_error() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let state_path = directory.path().join("state.json");
    let credentials = Arc::new(FakeCredentialStore::default());
    let (runtime, pair) = runtime(
        state_path.clone(),
        Arc::clone(&credentials),
        "https://drive.example.test",
    );

    let missing_credential = tauri::async_runtime::block_on(
        crate::application::linux::roots::refresh_authorized_roots(&runtime),
    )
    .expect_err("root discovery must require the paired credential");
    assert!(matches!(&missing_credential, DesktopError::NeedsReconnect));
    assert!(is_sync_admission_error(&missing_credential));
    assert!(matches!(
        persist_terminal_failure(&runtime, missing_credential)
            .expect("admission classification needs no persistence"),
        TerminalFailure::Admission(DesktopError::NeedsReconnect)
    ));
    assert_eq!(runtime.status(), SyncStatus::NeedsReconnect);
    let cancelled = persist_terminal_failure(&runtime, DesktopError::SyncCancelledForDisconnect)
        .expect("Disconnect cancellation needs no persistence");
    assert!(matches!(
        cancelled,
        TerminalFailure::Admission(DesktopError::SyncCancelledForDisconnect)
    ));
    assert!(runtime.coordinator.snapshot().last_error.is_none());
    assert!(!state_path.exists());

    credentials
        .set(
            &Runtime::credential_key(&pair.server_url, &pair.account_email),
            "test-bearer",
        )
        .expect("publish test credential");
    assert_eq!(runtime.status(), SyncStatus::Synced);
    assert!(runtime.coordinator.snapshot().last_error.is_none());

    let active_operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .expect("fixture lifecycle reservation");
    let busy = tauri::async_runtime::block_on(
        crate::application::linux::roots::refresh_authorized_roots(&runtime),
    )
    .expect_err("concurrent root discovery must preserve the active operation");
    assert!(matches!(&busy, DesktopError::SyncAlreadyRunning));
    assert!(is_sync_admission_error(&busy));
    assert!(runtime.coordinator.snapshot().last_error.is_none());
    assert!(matches!(
        runtime.coordinator.begin_run(),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    drop(active_operation);
    assert!(runtime.coordinator.begin_run().is_ok());
}

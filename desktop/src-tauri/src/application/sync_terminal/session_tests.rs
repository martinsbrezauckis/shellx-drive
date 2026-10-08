use std::{collections::BTreeMap, path::Path, sync::Arc};

use shellx_drive_desktop_core::{
    sync_pair_id, BaselineEntry, CredentialStore, DesktopError, DesktopState, FakeCredentialStore,
    Result as CoreResult, StateStore, SyncPair, SyncStatus,
};

use super::{
    failure::{persist_terminal_failure, TerminalFailure},
    session::{admit_persisted_all_roots, admit_user_session_response},
};
use crate::{application::Runtime, platform::PlatformServices, session_identity::SessionIdentity};

mod add_root;
mod setup;

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

fn pair(workspace_id: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        workspace_id: workspace_id.to_string(),
        workspace_name: workspace_id.to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: format!("/tmp/shellx-drive-session-rejection-{workspace_id}").into(),
        local_root_identity: None,
    }
}

fn unauthorized() -> DesktopError {
    DesktopError::Server {
        status: 401,
        message: "sign-in was not accepted".to_string(),
    }
}

#[test]
fn rejected_captured_bearer_requires_reconnect_without_touching_pair_state() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let state_path = directory.path().join("state.json");
    let completed_pair = pair("completed");
    let selected_pair = pair("selected");
    let mut state = DesktopState::default();
    state.configure_pair(completed_pair.clone()).unwrap();
    state.configure_pair(selected_pair.clone()).unwrap();
    StateStore::new(&state_path).save(&state).unwrap();
    let credentials = Arc::new(FakeCredentialStore::default());
    let identity = SessionIdentity::new(&selected_pair.server_url, &selected_pair.account_email);
    credentials
        .set(&identity.credential_key(), "captured")
        .unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(Arc::clone(&credentials))),
        StateStore::new(&state_path),
        state,
    );
    let mut run = runtime.coordinator.begin_run().unwrap();
    let selected_pair_id = run.selected_pair_id().unwrap();
    run.activate_configured_pair(&sync_pair_id(&completed_pair))
        .unwrap();
    run.record_success(
        BTreeMap::from([(
            "kept".to_string(),
            BaselineEntry {
                remote_id: "kept".to_string(),
                parent_id: None,
                relative_path: "kept".into(),
                kind: "file".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: None,
            },
        )]),
        chrono::Utc::now(),
    );
    let error = tauri::async_runtime::block_on(admit_persisted_all_roots(
        &runtime,
        &mut run,
        &selected_pair_id,
        &identity,
        "captured",
        unauthorized(),
    ))
    .expect_err("a proven 401 must require sign-in again");
    assert!(matches!(error, DesktopError::NeedsReconnect));
    let preserved = runtime.coordinator.snapshot();
    assert_eq!(preserved.pair.as_ref(), Some(&selected_pair));
    assert!(preserved.inactive_pairs.iter().any(|profile| {
        profile.pair == completed_pair && profile.baseline.contains_key("kept")
    }));
    assert_eq!(StateStore::new(&state_path).load().unwrap(), preserved);
    assert!(runtime.coordinator.begin_run().is_ok());

    assert!(credentials
        .get(&identity.credential_key())
        .unwrap()
        .is_none());
    assert_eq!(runtime.status(), SyncStatus::NeedsReconnect);
    assert_eq!(runtime.coordinator.snapshot(), preserved);
    assert_eq!(StateStore::new(&state_path).load().unwrap(), preserved);

    credentials
        .set(&identity.credential_key(), "replacement")
        .unwrap();
    let error = tauri::async_runtime::block_on(admit_user_session_response::<()>(
        &runtime,
        &identity,
        "captured",
        Err(unauthorized()),
    ))
    .expect_err("a replacement bearer must not be removed");
    assert!(matches!(error, DesktopError::NeedsReconnect));
    assert_eq!(
        credentials
            .get(&identity.credential_key())
            .unwrap()
            .as_deref(),
        Some("replacement")
    );
    assert!(matches!(
        persist_terminal_failure(&runtime, error).unwrap(),
        TerminalFailure::Admission(DesktopError::NeedsReconnect)
    ));
    assert_eq!(runtime.status(), SyncStatus::Synced);
    assert_eq!(runtime.coordinator.snapshot(), preserved);
    assert_eq!(StateStore::new(&state_path).load().unwrap(), preserved);

    let error = tauri::async_runtime::block_on(admit_user_session_response::<()>(
        &runtime,
        &identity,
        "replacement",
        Err(DesktopError::Server {
            status: 403,
            message: "access removed".to_string(),
        }),
    ))
    .expect_err("an authority removal is not a session rejection");
    assert!(matches!(error, DesktopError::Server { status: 403, .. }));
    assert_eq!(
        credentials
            .get(&identity.credential_key())
            .unwrap()
            .as_deref(),
        Some("replacement")
    );
}

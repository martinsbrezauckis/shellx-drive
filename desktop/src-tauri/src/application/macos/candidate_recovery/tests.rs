//! Native sign-in lifecycle regressions with in-memory credentials.

use std::{path::Path, sync::Arc};

use shellx_drive_desktop_core::{
    CredentialStore, DesktopState, FakeCredentialStore, RemoteSessionRecord, Result as CoreResult,
    StateStore,
};

use crate::application::{ConnectionManager, Runtime};
use crate::session_identity::SessionIdentity;

struct TestPlatform(FakeCredentialStore);

impl crate::platform::PlatformServices for TestPlatform {
    fn credentials(&self) -> &dyn CredentialStore {
        &self.0
    }
    fn desktop_agent_credentials(&self) -> &dyn CredentialStore {
        &self.0
    }
    fn desktop_agent_disconnect_credentials(&self) -> &dyn CredentialStore {
        &self.0
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

fn factory(store: StateStore, state: DesktopState) -> CoreResult<Runtime> {
    Ok(Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        store,
        state,
    ))
}

fn manager(directory: &Path) -> ConnectionManager {
    ConnectionManager::load(
        Arc::new(
            factory(
                StateStore::new(directory.join("state.json")),
                DesktopState::default(),
            )
            .unwrap(),
        ),
        factory,
    )
    .unwrap()
}

#[tokio::test]
async fn late_response_keeps_catalog_ownership_through_recovery_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let manager = manager(directory.path());
    manager
        .save_preferences("system".to_string(), false, 20)
        .unwrap();
    let id = manager.begin_connection("Work".to_string()).unwrap();
    manager
        .reserve_identity(&id, "https://drive.example.test", "work@example.test")
        .unwrap();
    let runtime = manager.resolve(Some(&id)).unwrap();
    let generation = runtime.auth_offboarding.admit_login().unwrap();
    let stopped = crate::application::request_disconnect_after_sync(&runtime)
        .await
        .unwrap();

    // Removal races a sign-in HTTP response while that request is held.
    manager.mark_removing(&id).unwrap();
    let _offboarding = runtime.auth_offboarding.begin_offboarding().unwrap();
    assert!(!runtime.auth_offboarding.may_publish(generation));
    assert!(runtime.coordinator.begin_lifecycle_operation().is_err());
    assert!(manager.finish_removal(&id).is_err());
    assert!(manager.resolve(Some(&id)).is_ok());

    // A late issued session whose logout needs retry retains an exact durable
    // locator before its request is released. The catalog must survive both
    // this terminal cleanup error and the next process startup.
    let record = RemoteSessionRecord::new(
        "https://drive.example.test",
        "work@example.test",
        "synthetic-late-session",
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .unwrap();
    runtime
        .coordinator
        .record_pending_candidate_session(record.clone(), chrono::Utc::now());
    runtime.set_candidate_recovery_pending(true);
    runtime.save().unwrap();
    drop(stopped);
    assert!(!runtime.coordinator.view_snapshot().disconnect_requested);
    assert!(manager.finish_removal(&id).is_err());
    assert!(runtime
        .platform
        .credentials()
        .get(&SessionIdentity::credential_key_for(
            "https://drive.example.test",
            "work@example.test",
        ))
        .unwrap()
        .is_none());

    let store = StateStore::new(directory.path().join("state.json"));
    let state = store.load().unwrap();
    let restarted =
        ConnectionManager::load(Arc::new(factory(store, state).unwrap()), factory).unwrap();
    let retained = restarted.resolve(Some(&id)).unwrap();
    assert_eq!(
        retained.coordinator.snapshot().pending_candidate_session,
        Some(record)
    );
    assert!(restarted.finish_removal(&id).is_err());
}

#[tokio::test]
async fn publication_promotes_held_request_without_opening_a_lifecycle_gap() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = factory(
        StateStore::new(directory.path().join("state.json")),
        DesktopState::default(),
    )
    .unwrap();
    let mut stopped = crate::application::request_disconnect_after_sync(&runtime)
        .await
        .unwrap();
    assert!(runtime.coordinator.begin_lifecycle_operation().is_err());

    let mut operation = super::begin_login_publication(&mut stopped).unwrap();
    let snapshot = runtime.coordinator.view_snapshot();
    assert!(snapshot.active_run);
    assert!(!snapshot.disconnect_requested);
    // Dropping the promoted request cannot release its lifecycle successor.
    drop(stopped);
    assert!(runtime.coordinator.begin_lifecycle_operation().is_err());
    operation.finish_state(DesktopState::default());
    assert!(runtime.coordinator.begin_lifecycle_operation().is_ok());
}

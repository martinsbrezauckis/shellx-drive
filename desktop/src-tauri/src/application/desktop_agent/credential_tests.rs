//! Exercise real registration publication/read/cleanup against a shared store.

use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use shellx_drive_desktop_core::{
    CredentialStore, DesktopAgentRegistration, DesktopState, FakeCredentialStore,
    Result as CoreResult, StateStore, SyncPair,
};

use super::{
    current_enrollment_fingerprint, device_credential, enable_after_local_confirmation,
    finish_confirmed_agent_retirement, publish_registered_agent, scoped_device_cleanup_slot,
    Runtime,
};

struct MemoryPlatform(Arc<FakeCredentialStore>);

impl crate::platform::PlatformServices for MemoryPlatform {
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

fn runtime(
    directory: &Path,
    server: &str,
    email: &str,
    credentials: Arc<FakeCredentialStore>,
) -> Runtime {
    std::fs::create_dir_all(directory).unwrap();
    let mut state = DesktopState::default();
    state
        .configure_pair(SyncPair {
            server_url: server.to_string(),
            account_email: email.to_string(),
            workspace_id: "workspace_fixture".into(),
            workspace_name: "Fixture".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: directory.join("root"),
            local_root_identity: None,
        })
        .unwrap();
    Runtime::from_loaded_state(
        Box::new(MemoryPlatform(credentials)),
        StateStore::new(directory.join("state.json")),
        state,
    )
}

async fn enroll(runtime: &Runtime, secret: &str) {
    let fingerprint = current_enrollment_fingerprint(&runtime.coordinator.snapshot()).unwrap();
    let registration = DesktopAgentRegistration {
        device_id: "device_shared".into(),
        device_credential: secret.to_string(),
        credential_expires_at: None,
    };
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    publish_registered_agent(
        runtime,
        &mut operation,
        &registration,
        fingerprint,
        || async { panic!("successful enrollment must not retire the registration") },
    )
    .await
    .unwrap();
}

fn finish_retirement(runtime: &Runtime) {
    let state = runtime.coordinator.snapshot();
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    finish_confirmed_agent_retirement(runtime, &mut operation, &state).unwrap();
}

#[tokio::test]
async fn device_credentials_isolate_servers_and_accounts_through_enrollment_reads_and_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(FakeCredentialStore::default());
    let first = runtime(
        &directory.path().join("first"),
        "https://first.example.test",
        "owner@example.test",
        Arc::clone(&store),
    );
    let second = runtime(
        &directory.path().join("second"),
        "https://second.example.test",
        "owner@example.test",
        Arc::clone(&store),
    );
    let other_account = runtime(
        &directory.path().join("third"),
        "https://first.example.test",
        "other@example.test",
        Arc::clone(&store),
    );
    enroll(&first, "sxd_device_first").await;
    enroll(&second, "sxd_device_second").await;
    enroll(&other_account, "sxd_device_third").await;
    assert_eq!(
        device_credential(&first).unwrap(),
        ("device_shared".into(), "sxd_device_first".into())
    );
    assert_eq!(device_credential(&second).unwrap().1, "sxd_device_second");
    assert_eq!(
        device_credential(&other_account).unwrap().1,
        "sxd_device_third"
    );
    assert!(store.get("device_shared").unwrap().is_none());
    let slots = [&first, &second, &other_account].map(|runtime| {
        scoped_device_cleanup_slot(&runtime.coordinator.snapshot())
            .unwrap()
            .unwrap()
    });
    assert!(slots.iter().all(|slot| slot.account_key.len() == 78));
    assert_ne!(slots[0], slots[1]);
    assert_ne!(slots[0], slots[2]);
    // The real local enable caller must recognize its own existing secret.
    enable_after_local_confirmation(&first).await.unwrap();
    finish_retirement(&first);
    assert!(store.get(&slots[0].account_key).unwrap().is_none());
    assert_eq!(device_credential(&second).unwrap().1, "sxd_device_second");
    assert_eq!(
        device_credential(&other_account).unwrap().1,
        "sxd_device_third"
    );
    finish_retirement(&second);
    finish_retirement(&other_account);
    assert!(slots
        .iter()
        .all(|slot| store.get(&slot.account_key).unwrap().is_none()));
}

#[tokio::test]
async fn device_credentials_registration_rollback_retains_another_connection_secret() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(FakeCredentialStore::default());
    let victim = runtime(
        &directory.path().join("victim"),
        "https://same.example.test",
        "victim@example.test",
        Arc::clone(&store),
    );
    enroll(&victim, "sxd_device_victim").await;
    let failed = runtime(
        &directory.path().join("failed"),
        "https://same.example.test",
        "failed@example.test",
        Arc::clone(&store),
    );
    // A non-directory state parent makes durable enrollment publication fail.
    std::fs::remove_dir_all(directory.path().join("failed")).unwrap();
    std::fs::write(directory.path().join("failed"), "fixture blocker").unwrap();
    let fingerprint = current_enrollment_fingerprint(&failed.coordinator.snapshot()).unwrap();
    let registration = DesktopAgentRegistration {
        device_id: "device_shared".into(),
        device_credential: "sxd_device_failed".into(),
        credential_expires_at: None,
    };
    let retired = AtomicBool::new(false);
    let mut operation = failed.coordinator.begin_lifecycle_operation().unwrap();
    assert!(publish_registered_agent(
        &failed,
        &mut operation,
        &registration,
        fingerprint,
        || async {
            retired.store(true, Ordering::Release);
            Ok(())
        }
    )
    .await
    .is_err());
    assert!(retired.load(Ordering::Acquire));
    assert!(!failed.coordinator.snapshot().desktop_agent_control.enabled);
    assert_eq!(device_credential(&victim).unwrap().1, "sxd_device_victim");
}

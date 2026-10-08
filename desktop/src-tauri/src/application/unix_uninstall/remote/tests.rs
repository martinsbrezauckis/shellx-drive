use std::future::ready;

use chrono::Utc;
use shellx_drive_desktop_core::{
    DisconnectCleanupIntent, DisconnectCredentialNamespace, DisconnectCredentialSlot,
    FakeCredentialStore,
};

use super::*;
use crate::application::{runtime::tests::TestPlatform, Runtime};

#[test]
fn restarted_pre_pair_disconnect_retires_session_before_exact_credential_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let identity = SessionIdentity::new("https://drive.example.test", "person@example.test");
    let key = identity.credential_key();
    let credentials = FakeCredentialStore::default();
    credentials.set(&key, "fixture-sign-in").unwrap();
    credentials
        .set("unrelated-non-drive-fixture", "retained-fixture")
        .unwrap();
    let mut initial = DesktopState::default();
    initial.publish_active_remote_session(RemoteSessionRecord {
        server_url: identity.server_url.clone(),
        account_email: identity.email.clone(),
        session_id: "saved-pre-pair-session".to_string(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
    });
    store.save(&initial).unwrap();
    let restored = store.load().unwrap();
    let runtime = Runtime::from_loaded_state(Box::new(TestPlatform(credentials)), store, restored);
    assert!(runtime.session.lock().unwrap().is_none());
    assert!(runtime.view().disconnect_available);

    tauri::async_runtime::block_on(async {
        let mut request = crate::application::request_disconnect_after_sync(&runtime)
            .await
            .unwrap();
        let mut operation = request.try_begin().unwrap().unwrap();
        let mut state = runtime.coordinator.snapshot();
        assert!(state.pairs().next().is_none());
        assert!(state.sync_root_base.is_none());
        let slot = DisconnectCredentialSlot {
            namespace: DisconnectCredentialNamespace::Canonical,
            account_key: key.clone(),
        };
        state
            .begin_disconnect_cleanup(
                DisconnectCleanupIntent::for_disconnect_pairs(Vec::new(), vec![slot.clone()])
                    .unwrap(),
            )
            .unwrap();
        runtime.store.save(&state).unwrap();
        operation.publish_persisted_state(state.clone()).unwrap();
        let stored = [StoredCredential {
            identity,
            token: runtime.platform.credentials().get(&key).unwrap().unwrap(),
            session_id: None,
        }];
        let mut logout_attempts = Vec::new();
        let failed = retire_stored_sessions(
            &runtime.store,
            &mut state,
            &stored,
            |_, _| ready(Err(DesktopError::InvalidState("unexpected revoke".into()))),
            |credential| {
                logout_attempts.push(credential.identity.credential_key());
                ready(Err(DesktopError::InvalidState("fixture offline".into())))
            },
        )
        .await;
        assert!(failed.is_err());
        let persisted_before = runtime.store.load().unwrap();
        assert!(persisted_before.active_remote_session.is_some());
        assert!(runtime.platform.credentials().get(&key).unwrap().is_some());
        assert!(!state
            .pending_disconnect_cleanup()
            .unwrap()
            .remote_retirement_confirmed());
        retire_stored_sessions(
            &runtime.store,
            &mut state,
            &stored,
            |_, _| ready(Err(DesktopError::InvalidState("unexpected revoke".into()))),
            |credential| {
                assert_eq!(credential.token, "fixture-sign-in");
                logout_attempts.push(credential.identity.credential_key());
                ready(Ok(LogoutOutcome::Revoked))
            },
        )
        .await
        .unwrap();
        assert_eq!(logout_attempts, [key.clone(), key.clone()]);
        let persisted_after = runtime.store.load().unwrap();
        assert!(persisted_after.active_remote_session.is_none());
        assert!(runtime.platform.credentials().get(&key).unwrap().is_some());
        state
            .pending_disconnect_cleanup_mut()
            .unwrap()
            .confirm_remote_retirement();
        state = state.into_disconnected(Utc::now());
        runtime.store.save(&state).unwrap();
        let mut removed = Vec::new();
        crate::application::linux::disconnect::complete_local_cleanup_with_slot_cleanup(
            &runtime.store,
            &mut state,
            DesktopState::finish_disconnect_cleanup,
            |candidate| {
                assert_eq!(candidate, &slot);
                runtime
                    .platform
                    .credentials()
                    .delete(&candidate.account_key)?;
                assert!(runtime
                    .platform
                    .credentials()
                    .get(&candidate.account_key)?
                    .is_none());
                removed.push(candidate.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(removed, [slot]);
        assert!(runtime.platform.credentials().get(&key).unwrap().is_none());
        assert_eq!(
            runtime
                .platform
                .credentials()
                .get("unrelated-non-drive-fixture")
                .unwrap()
                .as_deref(),
            Some("retained-fixture")
        );
        assert!(runtime.store.load().unwrap().uninstall_cleanup_ready());
        operation.finish_state(state);
    });
    assert!(!runtime.view().disconnect_available);
}

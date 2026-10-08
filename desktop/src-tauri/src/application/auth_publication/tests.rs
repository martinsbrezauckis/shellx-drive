use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
};

use shellx_drive_desktop_core::{AuthOffboardingGate, DesktopError};

use super::*;

fn pending(generation: u64) -> PendingLogin {
    PendingLogin {
        server_url: "https://drive.example.test".to_string(),
        email: "person@example.test".to_string(),
        // This test value stays in a stack-local, memory-only continuation.
        password: "test-only-ephemeral-password".to_string(),
        generation,
    }
}

fn assert_canceled(error: DesktopError) {
    assert!(error.to_string().contains(CANCELED_SIGN_IN));
}

#[test]
fn late_second_factor_result_cannot_restore_pending_login_after_new_login() {
    let gate = Arc::new(AuthOffboardingGate::default());
    let publication = Arc::new(tokio::sync::Mutex::new(()));
    let pending_login = Arc::new(Mutex::new(None));
    let old = gate.admit_login().unwrap();
    let held_publication = tauri::async_runtime::block_on(publication.lock());
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker_gate = Arc::clone(&gate);
    let worker_publication = Arc::clone(&publication);
    let worker_pending = Arc::clone(&pending_login);
    let worker = thread::spawn(move || {
        let result = tauri::async_runtime::block_on(publish_second_factor(
            &worker_gate,
            &worker_publication,
            &worker_pending,
            pending(old),
        ));
        sender.send(result).unwrap();
    });

    // The first request reached its terminal stage but is queued behind the
    // serializer while the replacement attempt invalidates its generation.
    let _new = gate.admit_login().unwrap();
    *pending_login.lock().unwrap() = None;
    drop(held_publication);

    assert_canceled(receiver.recv().unwrap().unwrap_err());
    worker.join().unwrap();
    assert!(pending_login.lock().unwrap().is_none());
}

#[test]
fn late_second_factor_result_cannot_restore_pending_login_after_disconnect() {
    tauri::async_runtime::block_on(async {
        let gate = AuthOffboardingGate::default();
        let publication = tokio::sync::Mutex::new(());
        let pending_login = Mutex::new(None);
        let old = gate.admit_login().unwrap();

        let offboarding = gate.begin_offboarding().unwrap();
        let error = publish_second_factor(&gate, &publication, &pending_login, pending(old))
            .await
            .unwrap_err();

        assert_canceled(error);
        assert!(pending_login.lock().unwrap().is_none());
        drop(offboarding);
    });
}

#[test]
fn late_authenticated_result_is_refused_after_new_login() {
    tauri::async_runtime::block_on(async {
        let gate = AuthOffboardingGate::default();
        let publication = tokio::sync::Mutex::new(());
        let old = gate.admit_login().unwrap();

        let _new = gate.admit_login().unwrap();
        assert_canceled(lock_current(&gate, &publication, old).await.unwrap_err());
    });
}

#[test]
fn late_authenticated_result_is_refused_after_disconnect_latches() {
    tauri::async_runtime::block_on(async {
        let gate = AuthOffboardingGate::default();
        let publication = tokio::sync::Mutex::new(());
        let old = gate.admit_login().unwrap();

        let offboarding = gate.begin_offboarding().unwrap();
        assert_canceled(lock_current(&gate, &publication, old).await.unwrap_err());
        drop(offboarding);
    });
}

use super::super::session::admit_user_session_response_during_publication;
use super::*;

fn setup_runtime() -> (
    tempfile::TempDir,
    Arc<FakeCredentialStore>,
    Runtime,
    SessionIdentity,
) {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let credentials = Arc::new(FakeCredentialStore::default());
    let identity = SessionIdentity::new("https://drive.example.test", "person@example.test");
    credentials
        .set(&identity.credential_key(), "captured")
        .unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(Arc::clone(&credentials))),
        StateStore::new(directory.path().join("state.json")),
        DesktopState::default(),
    );
    *runtime.session.lock().expect("session lock") = Some(identity.clone());
    (directory, credentials, runtime, identity)
}

#[test]
fn rejected_unpaired_bearer_retires_only_its_current_setup_session() {
    let (_directory, credentials, runtime, identity) = setup_runtime();
    let publication = tauri::async_runtime::block_on(runtime.auth_publication.lock());
    let error = admit_user_session_response_during_publication::<()>(
        &runtime,
        &identity,
        "captured",
        Err(unauthorized()),
    )
    .expect_err("a setup 401 must require sign-in again");
    drop(publication);

    assert!(matches!(error, DesktopError::NeedsReconnect));
    assert!(credentials
        .get(&identity.credential_key())
        .unwrap()
        .is_none());
    assert!(matches!(
        runtime.current_session(),
        Err(DesktopError::NeedsSetup)
    ));
    let view = runtime.view();
    assert_eq!(view.status, "needs_setup");
    assert!(view.account.is_empty());
    assert!(view.server_url.is_empty());

    let newer = SessionIdentity::new("https://drive.example.test", "newer@example.test");
    credentials
        .set(&identity.credential_key(), "captured-again")
        .unwrap();
    credentials
        .set(&newer.credential_key(), "replacement")
        .unwrap();
    *runtime.session.lock().expect("session lock") = Some(newer.clone());
    let error = tauri::async_runtime::block_on(admit_user_session_response::<()>(
        &runtime,
        &identity,
        "captured-again",
        Err(unauthorized()),
    ))
    .expect_err("a stale setup 401 must not retire a newer sign-in");

    assert!(matches!(error, DesktopError::NeedsReconnect));
    assert_eq!(runtime.current_session().unwrap(), newer);
    assert_eq!(
        credentials
            .get(&identity.credential_key())
            .unwrap()
            .as_deref(),
        Some("captured-again")
    );
    assert_eq!(
        credentials.get(&newer.credential_key()).unwrap().as_deref(),
        Some("replacement")
    );
}

#[test]
fn user_session_401_can_reacquire_released_publication_lock() {
    let (_directory, credentials, runtime, identity) = setup_runtime();
    let publication = tauri::async_runtime::block_on(runtime.auth_publication.lock());
    runtime
        .require_captured_setup_session_during_publication(&identity, "captured")
        .expect("the captured setup response still belongs to this session");
    drop(publication);

    let error = tauri::async_runtime::block_on(admit_user_session_response::<()>(
        &runtime,
        &identity,
        "captured",
        Err(unauthorized()),
    ))
    .expect_err("session admission can reacquire publication after its caller releases it");
    assert!(matches!(error, DesktopError::NeedsReconnect));
    assert!(credentials
        .get(&identity.credential_key())
        .unwrap()
        .is_none());
}

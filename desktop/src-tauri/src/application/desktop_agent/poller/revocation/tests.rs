use shellx_drive_desktop_core::{CredentialStore, DesktopError, DesktopState, FakeCredentialStore};

use super::{
    clear_exact_current_device_after_confirmed_revocation, is_device_bearer_unauthorized,
    missing_device_credential_id,
};

#[test]
fn only_a_device_bearer_unauthorized_response_starts_reconciliation() {
    assert!(is_device_bearer_unauthorized(&DesktopError::Server {
        status: 401,
        message: "sign-in was not accepted".to_string(),
    }));
    assert!(!is_device_bearer_unauthorized(&DesktopError::Server {
        status: 403,
        message: "the account cannot access this Drive location".to_string(),
    }));
    assert!(!is_device_bearer_unauthorized(&DesktopError::Server {
        status: 409,
        message: "Drive changed this item before the update could be applied".to_string(),
    }));
}

#[test]
fn missing_credential_after_an_unsaved_clear_retries_only_when_revocation_is_confirmed() {
    let store = FakeCredentialStore::default();
    let mut persisted = DesktopState::default();
    persisted
        .desktop_agent_control
        .enroll("device_current".to_string(), None, "a".repeat(64))
        .unwrap();
    persisted
        .record_desktop_update_restart_for_agent(
            "1.2.3".to_string(),
            "candidate_current".to_string(),
            "command_current".to_string(),
        )
        .unwrap();
    let key = persisted
        .desktop_agent_control
        .credential_key
        .clone()
        .unwrap();
    store.set(&key, "sxd_device_fixture").unwrap();
    store.delete(&key).unwrap();

    // This models the post-delete state-save failure/crash: the secret is
    // gone but the last durable state is still enabled on the next start.
    assert_eq!(
        missing_device_credential_id(&persisted.desktop_agent_control, &store, &key).unwrap(),
        Some("device_current".to_string())
    );
    let mut unsaved_attempt = persisted.clone();
    assert!(clear_exact_current_device_after_confirmed_revocation(
        &mut unsaved_attempt,
        "device_current",
        true
    ));
    assert!(persisted.desktop_agent_control.enabled);
    assert!(persisted.pending_desktop_update_restart.is_some());

    assert!(!clear_exact_current_device_after_confirmed_revocation(
        &mut persisted,
        "device_other",
        true
    ));
    assert!(persisted.pending_desktop_update_restart.is_some());

    // A missing credential with a live/other server readback is not a
    // revocation confirmation and must retain the durable enrollment.
    assert!(!clear_exact_current_device_after_confirmed_revocation(
        &mut persisted,
        "device_current",
        false
    ));
    assert_eq!(
        persisted.desktop_agent_control.device_id.as_deref(),
        Some("device_current")
    );
    assert!(persisted.pending_desktop_update_restart.is_some());

    assert!(clear_exact_current_device_after_confirmed_revocation(
        &mut persisted,
        "device_current",
        true
    ));
    assert!(!persisted.desktop_agent_control.enabled);
    assert!(persisted.desktop_agent_control.device_id.is_none());
    assert!(persisted.desktop_agent_control.command_journal.is_empty());
    assert!(persisted.pending_desktop_update_restart.is_none());
}

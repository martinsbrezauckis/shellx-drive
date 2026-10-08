use super::*;
use crate::DesktopState;
use chrono::Utc;
use std::path::PathBuf;

fn canonical_slot(account_key: &str) -> DisconnectCredentialSlot {
    DisconnectCredentialSlot {
        namespace: DisconnectCredentialNamespace::Canonical,
        account_key: account_key.to_string(),
    }
}

fn pair() -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: PathBuf::from("C:/Drive"),
        local_root_identity: None,
    }
}

#[test]
fn cleanup_intent_keeps_only_exact_non_secret_retry_locators() {
    let mut intent = DisconnectCleanupIntent::for_disconnect(
        Some(&pair()),
        vec![canonical_slot(
            "https://drive.example.test|owner@example.test",
        )],
    )
    .unwrap();

    assert_eq!(
        intent.marker.as_ref().unwrap().local_root,
        PathBuf::from("C:/Drive")
    );
    assert_eq!(
        intent
            .next_credential_slot()
            .map(|slot| (&slot.namespace, slot.account_key.as_str())),
        Some((
            &DisconnectCredentialNamespace::Canonical,
            "https://drive.example.test|owner@example.test"
        ))
    );
    assert!(!intent.remote_retirement_confirmed());
    intent.confirm_remote_retirement();
    intent.acknowledge_marker();
    intent
        .acknowledge_credential_slot(&canonical_slot(
            "https://drive.example.test|owner@example.test",
        ))
        .unwrap();
    assert!(intent.is_complete());
}

#[test]
fn cleanup_intent_cannot_complete_before_remote_retirement() {
    let intent = DisconnectCleanupIntent::for_disconnect(None, Vec::new()).unwrap();
    assert!(!intent.is_complete());
}

#[test]
fn cleanup_phase_changes_only_after_remote_retirement_is_confirmed() {
    let mut intent = DisconnectCleanupIntent::for_disconnect(None, Vec::new()).unwrap();
    assert!(!intent.remote_retirement_confirmed());
    intent.confirm_remote_retirement();
    assert!(intent.remote_retirement_confirmed());
}

#[test]
fn disconnected_projection_retains_confirmed_cleanup_for_retry() {
    let mut intent = DisconnectCleanupIntent::for_disconnect(None, Vec::new()).unwrap();
    intent.confirm_remote_retirement();
    let state = DesktopState {
        pending_disconnect_cleanup: Some(intent.clone()),
        ..DesktopState::default()
    }
    .into_disconnected(Utc::now());

    assert_eq!(state.pending_disconnect_cleanup, Some(intent));
}

#[test]
fn cleanup_intent_rejects_ambiguous_slot_ordering() {
    assert!(DisconnectCleanupIntent::for_disconnect(
        None,
        vec![canonical_slot("same"), canonical_slot("same")],
    )
    .is_err());
    assert!(DisconnectCleanupIntent::for_disconnect(
        None,
        vec![canonical_slot("second"), canonical_slot("first")],
    )
    .is_err());
}

#[test]
fn cleanup_intent_rejects_empty_or_cross_namespace_ambiguous_slots() {
    assert!(DisconnectCleanupIntent::for_disconnect(None, vec![canonical_slot("")]).is_err());
    assert!(DisconnectCleanupIntent::for_disconnect(
        None,
        vec![
            DisconnectCredentialSlot {
                namespace: DisconnectCredentialNamespace::PendingCandidate,
                account_key: "same".to_string(),
            },
            canonical_slot("same"),
        ],
    )
    .is_err());
}

#[path = "tests/locations.rs"]
mod locations;

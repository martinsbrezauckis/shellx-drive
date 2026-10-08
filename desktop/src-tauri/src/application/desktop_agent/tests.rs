use std::path::PathBuf;

use shellx_drive_desktop_core::{
    desktop_agent_enrollment_fingerprint, desktop_agent_pair_fingerprint, sync_pair_id,
    DesktopState, SyncPair,
};

use super::{current_enrollment_fingerprint, require_current_enrollment_binding};

fn pair(workspace_id: &str, root_id: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test/".to_string(),
        account_email: "OWNER@example.test".to_string(),
        workspace_id: workspace_id.to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: Some(root_id.to_string()),
        remote_root_name: Some("Root".to_string()),
        local_root: PathBuf::from(format!("/fixture/{root_id}")),
        local_root_identity: None,
    }
}

#[test]
fn switching_same_account_roots_retains_the_enrollment_assertion() {
    let first = pair("workspace_1", "root_1");
    let second = pair("workspace_2", "root_2");
    let enrollment = desktop_agent_enrollment_fingerprint(&first.server_url, &first.account_email);
    let mut state = DesktopState::default();
    state.configure_pair(first).expect("first root");
    state.configure_pair(second).expect("second root");
    state
        .desktop_agent_control
        .enroll("device_1".to_string(), None, enrollment.clone())
        .expect("enrollment");

    assert_eq!(current_enrollment_fingerprint(&state).unwrap(), enrollment);
    let first_id = state
        .inactive_pairs
        .first()
        .expect("inactive first root")
        .pair
        .clone();
    state
        .activate_pair(&sync_pair_id(&first_id))
        .expect("switch root");
    let after_switch = current_enrollment_fingerprint(&state).unwrap();
    assert_eq!(after_switch, enrollment);
    require_current_enrollment_binding(&state, &after_switch).expect("enrollment remains bound");
}

#[test]
fn cross_identity_pair_and_legacy_root_binding_are_denied() {
    let first = pair("workspace_1", "root_1");
    for mut other_identity in [pair("workspace_2", "root_2"), pair("workspace_3", "root_3")] {
        if other_identity.workspace_id == "workspace_2" {
            other_identity.server_url = "https://other.example.test".to_string();
        } else {
            other_identity.account_email = "other@example.test".to_string();
        }
        let mut state = DesktopState::default();
        state.configure_pair(first.clone()).expect("first root");
        assert!(state.configure_pair(other_identity).is_err());
    }

    let mut state = DesktopState::default();
    state.configure_pair(first.clone()).expect("first root");
    state
        .desktop_agent_control
        .enroll(
            "device_1".to_string(),
            None,
            desktop_agent_pair_fingerprint(&first),
        )
        .expect("legacy-shaped enrollment");
    let current = current_enrollment_fingerprint(&state).unwrap();
    assert_ne!(
        state.desktop_agent_control.pair_fingerprint.as_deref(),
        Some(current.as_str())
    );
    assert!(require_current_enrollment_binding(&state, &current).is_err());
}

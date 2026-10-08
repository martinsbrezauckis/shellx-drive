use super::super::*;
use crate::DesktopState;

#[test]
fn restart_readback_clears_only_the_observed_browser_target() {
    let mut state = DesktopState::default();
    state
        .record_desktop_update_restart("1.2.3".to_string(), "candidate-1".to_string())
        .unwrap();
    assert_eq!(
        state.read_desktop_update_restart("1.2.2").unwrap(),
        DesktopUpdateRestartReadback::Unconfirmed {
            target_version: "1.2.3".to_string(),
            candidate_id: Some("candidate-1".to_string()),
            agent_command_id: None,
        }
    );
    assert!(state.pending_desktop_update_restart.is_some());
    assert_eq!(
        state.read_desktop_update_restart("1.2.3").unwrap(),
        DesktopUpdateRestartReadback::Applied {
            version: "1.2.3".to_string(),
            candidate_id: Some("candidate-1".to_string()),
            agent_command_id: None,
        }
    );
    assert!(state.pending_desktop_update_restart.is_none());
}

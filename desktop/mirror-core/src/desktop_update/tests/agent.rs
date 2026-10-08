use super::super::*;
use crate::DesktopState;
#[test]
fn agent_readback_requires_the_bound_command_to_complete() {
    let mut state = DesktopState::default();
    state
        .record_desktop_update_restart_for_agent(
            "1.2.3".to_string(),
            "candidate-1".to_string(),
            "command-1".to_string(),
        )
        .unwrap();
    assert_eq!(
        state.read_desktop_update_restart("1.2.3").unwrap(),
        DesktopUpdateRestartReadback::Applied {
            version: "1.2.3".to_string(),
            candidate_id: Some("candidate-1".to_string()),
            agent_command_id: Some("command-1".to_string()),
        }
    );
    assert!(state.pending_desktop_update_restart.is_some());
    assert!(state
        .complete_desktop_update_restart_for_agent("candidate-2", "command-1")
        .is_err());
    assert!(state
        .complete_desktop_update_restart_for_agent("candidate-1", "command-2")
        .is_err());
    state
        .complete_desktop_update_restart_for_agent("candidate-1", "command-1")
        .unwrap();
    assert!(state.pending_desktop_update_restart.is_none());
}

#[test]
fn restart_intent_rejects_unbounded_or_control_values() {
    assert!(DesktopUpdateRestartIntent::new("\n".to_string(), "candidate-1".to_string()).is_err());
    assert!(DesktopUpdateRestartIntent::new("1.2.3".to_string(), "\n".to_string()).is_err());
    assert!(DesktopUpdateRestartIntent::for_agent(
        "1.2.3".to_string(),
        "candidate-1".to_string(),
        "\n".to_string()
    )
    .is_err());
}

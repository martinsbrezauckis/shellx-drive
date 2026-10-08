use crate::{DesktopAgentClaim, DesktopAgentCommandKind};

#[test]
fn disconnect_capability_is_required_and_never_crosses_command_kinds() {
    let missing = serde_json::from_value::<DesktopAgentClaim>(serde_json::json!({
        "command_id": "command_1", "lease_id": "lease_1",
        "lease_expires_at": "2036-09-07T12:00:00Z", "kind": "disconnect", "payload": {},
        "disconnect_completion_expires_at": "2036-09-07T12:10:00Z"
    }));
    assert!(missing.is_err());

    let missing_deadline = serde_json::from_value::<DesktopAgentClaim>(serde_json::json!({
        "command_id": "command_1", "lease_id": "lease_1",
        "lease_expires_at": "2036-09-07T12:00:00Z", "kind": "disconnect", "payload": {},
        "disconnect_completion_capability": "sxd_disconnect_fixture"
    }));
    assert!(missing_deadline.is_err());

    let cross_command = serde_json::from_value::<DesktopAgentClaim>(serde_json::json!({
        "command_id": "command_1", "lease_id": "lease_1",
        "lease_expires_at": "2036-09-07T12:00:00Z", "kind": "sync_now", "payload": {},
        "disconnect_completion_expires_at": "2036-09-07T12:10:00Z"
    }));
    assert!(cross_command.is_err());

    assert_eq!(
        super::claim(DesktopAgentCommandKind::Disconnect, serde_json::json!({}))
            .disconnect_completion_capability
            .as_deref(),
        Some("sxd_disconnect_fixture")
    );
    assert!(
        super::claim(DesktopAgentCommandKind::Disconnect, serde_json::json!({}))
            .disconnect_completion_expires_at
            .is_some()
    );
}

use super::*;

fn cancellation_conflict(body: serde_json::Value) -> bool {
    is_cancellation_command_event_conflict(&serde_json::to_vec(&body).unwrap())
}

#[test]
fn exact_cancellation_conflict_is_the_only_typed_command_event_disposition() {
    let body = serde_json::json!({
        "error": DESKTOP_AGENT_CANCELLATION_REQUESTED,
        "message": "the command was cancelled",
    });
    assert!(cancellation_conflict(body));
}

#[test]
fn other_conflict_codes_never_become_cancellation() {
    for body in [
        serde_json::json!({"error": "conflict"}),
        serde_json::json!({"error": "desktop_agent_disconnect_capability_expired"}),
        serde_json::json!({"message": "cancellation text without the fixed code"}),
        serde_json::json!({"error": DESKTOP_AGENT_CANCELLATION_REQUESTED, "extra": true}),
    ] {
        assert!(!cancellation_conflict(body));
    }
}

#[test]
fn oversized_command_event_error_never_becomes_a_cancellation_disposition() {
    let body = vec![b'x'; MAX_DESKTOP_AGENT_COMMAND_EVENT_ERROR_BYTES + 1];
    assert!(!is_cancellation_command_event_conflict(&body));
}

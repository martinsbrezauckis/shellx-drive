use crate::desktop_agent::{
    validate_result_payload, DesktopAgentCommandPayload, DesktopAgentResultPayload,
    DesktopAgentReviewAction,
};

use super::validate_result_matches_payload;

fn prepared(pair_id: &str) -> DesktopAgentResultPayload {
    DesktopAgentResultPayload::ReviewPrepared {
        pair_id: Some(pair_id.to_string()),
        review_id: "review_1".to_string(),
        action: DesktopAgentReviewAction::RemoveLocalCopy,
        prepared_confirmation_id: "confirmation_1".to_string(),
        fingerprint: "a".repeat(64),
    }
}

#[test]
fn review_terminal_must_echo_the_requested_pair() {
    let payload = DesktopAgentCommandPayload::PrepareReviewAction {
        pair_id: Some("pair_1".to_string()),
        review_id: "review_1".to_string(),
        action: DesktopAgentReviewAction::RemoveLocalCopy,
    };

    assert!(validate_result_matches_payload(&payload, &prepared("pair_1")).is_ok());
    assert!(validate_result_matches_payload(&payload, &prepared("pair_2")).is_err());
}

#[test]
fn historical_unbound_review_result_stays_readable_but_cannot_terminalize() {
    let historical: DesktopAgentResultPayload = serde_json::from_value(serde_json::json!({
        "kind": "review_prepared",
        "review_id": "review_1",
        "action": "remove_local_copy",
        "prepared_confirmation_id": "confirmation_1",
        "fingerprint": "a".repeat(64),
    }))
    .unwrap();
    let payload = DesktopAgentCommandPayload::PrepareReviewAction {
        pair_id: Some("pair_1".to_string()),
        review_id: "review_1".to_string(),
        action: DesktopAgentReviewAction::RemoveLocalCopy,
    };

    assert!(validate_result_payload(&payload, &historical).is_err());
    assert!(validate_result_matches_payload(&payload, &historical).is_err());
}

#[test]
fn historical_unbound_review_payloads_stay_readable_but_unclaimable() {
    for payload in [
        serde_json::json!({
            "kind": "prepare_review_action",
            "review_id": "review_1",
            "action": "remove_local_copy",
        }),
        serde_json::json!({
            "kind": "confirm_review_action",
            "review_id": "review_1",
            "action": "remove_local_copy",
            "prepared_confirmation_id": "confirmation_1",
            "fingerprint": "a".repeat(64),
        }),
    ] {
        let payload: DesktopAgentCommandPayload = serde_json::from_value(payload).unwrap();
        assert!(!payload.is_claimable());
    }
}

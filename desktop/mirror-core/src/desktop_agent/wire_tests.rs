use super::*;
use crate::ReviewAction;

#[path = "wire_tests/disconnect.rs"]
mod disconnect;
#[path = "wire_tests/readback.rs"]
mod readback;

pub(super) fn claim(
    kind: DesktopAgentCommandKind,
    payload: serde_json::Value,
) -> DesktopAgentClaim {
    let mut wire = serde_json::json!({
        "command_id": "command_1",
        "lease_id": "lease_1",
        "lease_expires_at": "2036-09-07T12:00:00Z",
        "kind": kind,
        "payload": payload,
    });
    if kind == DesktopAgentCommandKind::Disconnect {
        wire["disconnect_completion_capability"] = serde_json::json!("sxd_disconnect_fixture");
        wire["disconnect_completion_expires_at"] = serde_json::json!("2036-09-07T12:10:00Z");
    }
    serde_json::from_value(wire).unwrap()
}

#[test]
fn wire_payload_decoder_uses_outer_kind_for_every_supported_command() {
    let fingerprint = "a".repeat(64);
    let cases = vec![
        (
            DesktopAgentCommandKind::DesktopView,
            serde_json::json!({}),
            DesktopAgentCommand::DesktopView {
                page: DesktopAgentDesktopViewPageRequest::default(),
            },
        ),
        (
            DesktopAgentCommandKind::SyncNow,
            serde_json::json!({}),
            DesktopAgentCommand::SyncNow,
        ),
        (
            DesktopAgentCommandKind::RecheckReviews,
            serde_json::json!({}),
            DesktopAgentCommand::RecheckReviews,
        ),
        (
            DesktopAgentCommandKind::SetPaused,
            serde_json::json!({"paused": true}),
            DesktopAgentCommand::SetPaused { paused: true },
        ),
        (
            DesktopAgentCommandKind::SetLaunchAtLogin,
            serde_json::json!({"enabled": false}),
            DesktopAgentCommand::SetLaunchAtLogin { enabled: false },
        ),
        (
            DesktopAgentCommandKind::PrepareReviewAction,
            serde_json::json!({"pair_id": "pair_1", "review_id": "review_1", "action": "remove_local_copy"}),
            DesktopAgentCommand::PrepareReviewAction {
                pair_id: "pair_1".to_string(),
                review_id: "review_1".to_string(),
                action: ReviewAction::RemoveLocalCopy,
            },
        ),
        (
            DesktopAgentCommandKind::ConfirmReviewAction,
            serde_json::json!({"pair_id": "pair_1", "review_id": "review_1", "action": "remove_local_copy", "prepared_confirmation_id": "confirm_1", "fingerprint": fingerprint}),
            DesktopAgentCommand::ConfirmReviewAction {
                pair_id: "pair_1".to_string(),
                review_id: "review_1".to_string(),
                action: ReviewAction::RemoveLocalCopy,
                prepared_confirmation_id: "confirm_1".to_string(),
                fingerprint: "a".repeat(64),
            },
        ),
        (
            DesktopAgentCommandKind::CheckDesktopUpdate,
            serde_json::json!({}),
            DesktopAgentCommand::CheckDesktopUpdate,
        ),
        (
            DesktopAgentCommandKind::InstallDesktopUpdate,
            serde_json::json!({"candidate_id": "candidate_1"}),
            DesktopAgentCommand::InstallDesktopUpdate {
                candidate_id: "candidate_1".to_string(),
            },
        ),
        (
            DesktopAgentCommandKind::Disconnect,
            serde_json::json!({}),
            DesktopAgentCommand::Disconnect,
        ),
        (
            DesktopAgentCommandKind::OpenLocalFolder,
            serde_json::json!({}),
            DesktopAgentCommand::OpenLocalFolder { pair_id: None },
        ),
        (
            DesktopAgentCommandKind::OpenDrive,
            serde_json::json!({}),
            DesktopAgentCommand::OpenDrive { pair_id: None },
        ),
        (
            DesktopAgentCommandKind::DiscoverRoots,
            serde_json::json!({}),
            DesktopAgentCommand::DiscoverRoots {
                page: DesktopAgentRootsPageRequest::default(),
            },
        ),
        (
            DesktopAgentCommandKind::StartPair,
            serde_json::json!({"workspace_id": "workspace_1"}),
            DesktopAgentCommand::StartPair {
                workspace_id: "workspace_1".to_string(),
            },
        ),
        (
            DesktopAgentCommandKind::SelectPair,
            serde_json::json!({"pair_id": "pair_1"}),
            DesktopAgentCommand::SelectPair {
                pair_id: "pair_1".to_string(),
            },
        ),
        (
            DesktopAgentCommandKind::ValidateServer,
            serde_json::json!({}),
            DesktopAgentCommand::ValidateServer,
        ),
        (
            DesktopAgentCommandKind::ContinueLogin,
            serde_json::json!({}),
            DesktopAgentCommand::RequiresLocalGesture(DesktopAgentLocalGesture::ContinueLogin),
        ),
        (
            DesktopAgentCommandKind::ContinueMfa,
            serde_json::json!({}),
            DesktopAgentCommand::RequiresLocalGesture(DesktopAgentLocalGesture::ContinueMfa),
        ),
    ];
    for (kind, payload, expected) in cases {
        assert_eq!(claim(kind, payload).parse_command().unwrap(), expected);
    }
}

#[test]
fn pair_actions_remain_distinct_and_empty_payloads_reject_extra_fields() {
    assert_eq!(
        claim(
            DesktopAgentCommandKind::OpenLocalFolder,
            serde_json::json!({"pair_id": "pair_1"})
        )
        .parse_command()
        .unwrap(),
        DesktopAgentCommand::OpenLocalFolder {
            pair_id: Some("pair_1".to_string())
        },
    );
    assert_eq!(
        claim(
            DesktopAgentCommandKind::OpenDrive,
            serde_json::json!({"pair_id": "pair_1"})
        )
        .parse_command()
        .unwrap(),
        DesktopAgentCommand::OpenDrive {
            pair_id: Some("pair_1".to_string())
        },
    );
    let invalid = serde_json::from_value::<DesktopAgentClaim>(serde_json::json!({
        "command_id": "command_1", "lease_id": "lease_1", "lease_expires_at": "2036-09-07T12:00:00Z",
        "kind": "desktop_view", "payload": { "pair_id": "pair_1" }
    }));
    assert!(invalid.is_err());
}

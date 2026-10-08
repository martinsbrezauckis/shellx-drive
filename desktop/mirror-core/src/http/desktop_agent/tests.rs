use super::*;
use crate::{DesktopAgentObservedStatus, DesktopAgentProgressPhase};

fn assertion() -> DesktopAgentDeviceAssertion {
    DesktopAgentDeviceAssertion {
        app_version: "1.0.0".to_string(),
        pair_fingerprint: "a".repeat(64),
        status: DesktopAgentObservedStatus::Ready,
        pending_disconnect_cleanup: false,
        candidate_recovery: false,
        last_terminal_command_id: None,
    }
}

#[test]
fn registration_serializes_the_direct_server_contract() {
    let body = serde_json::to_value(RegisterDeviceRequest {
        platform: DesktopAgentPlatform::Linux,
        assertion: &assertion(),
    })
    .unwrap();

    assert_eq!(body["platform"], "linux");
    assert_eq!(body["status"], "ready");
    assert_eq!(body["app_version"], "1.0.0");
    assert!(body.get("assertion").is_none());
}

#[test]
fn command_events_nest_the_device_assertion() {
    let binding = assertion();
    let body = serde_json::to_value(CommandEventRequest::Progress {
        lease_id: "lease_1",
        event_sequence: 2,
        assertion: &binding,
        phase: DesktopAgentProgressPhase::Syncing,
        progress_basis_points: Some(5000),
    })
    .unwrap();

    assert_eq!(body["lease_id"], "lease_1");
    assert_eq!(body["phase"], "syncing");
    assert_eq!(body["assertion"]["status"], "ready");
    assert!(body.get("pair_fingerprint").is_none());
}

#[test]
fn shared_broker_fixture_matches_real_enrollment_lease_renewal_and_terminal_types() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("desktop-agent-claim-set-paused.json")).unwrap();
    let registration = serde_json::to_value(RegisterDeviceRequest {
        platform: DesktopAgentPlatform::Linux,
        assertion: &assertion(),
    })
    .unwrap();
    assert_eq!(registration, fixture["registration_request"]);

    let response: ClaimResponse =
        serde_json::from_value(fixture["claim_response"].clone()).unwrap();
    let claim = response.claim.expect("fixture contains one claim");
    assert_eq!(
        claim.parse_command().unwrap(),
        crate::DesktopAgentCommand::SetPaused { paused: true }
    );

    let binding = assertion();
    let acknowledgement = serde_json::to_value(CommandEventRequest::Acknowledgement {
        lease_id: "lease_1",
        event_sequence: 1,
        assertion: &binding,
    })
    .unwrap();
    assert_eq!(acknowledgement, fixture["acknowledge_request"]);

    let initial_progress =
        serde_json::to_value(CommandEventRequest::from(DesktopAgentProgressReport {
            command_id: "command_1",
            lease_id: "lease_1",
            event_sequence: 2,
            assertion: &binding,
            phase: DesktopAgentProgressPhase::Accepted,
            progress_basis_points: None,
        }))
        .unwrap();
    assert_eq!(initial_progress, fixture["initial_progress_request"]);

    let renewal = serde_json::to_value(CommandEventRequest::from(DesktopAgentProgressReport {
        command_id: "command_1",
        lease_id: "lease_1",
        event_sequence: 3,
        assertion: &binding,
        phase: DesktopAgentProgressPhase::Syncing,
        progress_basis_points: None,
    }))
    .unwrap();
    assert_eq!(renewal, fixture["renewal_progress_request"]);

    let mut terminal_assertion = binding.clone();
    terminal_assertion.last_terminal_command_id = Some("command_1".to_string());
    let result = crate::DesktopAgentResultPayload::Pause { paused: true };
    let terminal_retry =
        serde_json::to_value(CommandEventRequest::from(DesktopAgentTerminalReport {
            command_id: "command_1",
            lease_id: "lease_1",
            event_sequence: 4,
            assertion: &terminal_assertion,
            status: crate::DesktopAgentTerminalStatus::Succeeded,
            terminal_code: crate::DesktopAgentTerminalCode::Completed,
            result_code: Some(crate::DesktopAgentResultCode::PausePersisted),
            result: Some(&result),
        }))
        .unwrap();
    assert_eq!(terminal_retry, fixture["terminal_retry_request"]);
}

#[test]
fn routes_reject_untrusted_identifier_segments() {
    assert!(bounded_route_id("device", "../other").is_err());
    assert!(bounded_route_segment("operation", "claim/other").is_err());
}

#[test]
fn external_revocation_requires_the_exact_owner_readback_device() {
    let response: OwnerDeviceListResponse = serde_json::from_value(serde_json::json!({
        "devices": [
            {"id": "device_other", "state": "revoked"},
            {"id": "device_current", "state": "revoked"}
        ]
    }))
    .unwrap();

    assert!(exact_device_is_revoked(response, "device_current").unwrap());
}

#[test]
fn external_revocation_does_not_clear_for_missing_or_non_revoked_devices() {
    let active: OwnerDeviceListResponse = serde_json::from_value(serde_json::json!({
        "devices": [{"id": "device_current", "state": "active"}]
    }))
    .unwrap();
    assert!(!exact_device_is_revoked(active, "device_current").unwrap());

    let missing: OwnerDeviceListResponse = serde_json::from_value(serde_json::json!({
        "devices": [{"id": "device_other", "state": "revoked"}]
    }))
    .unwrap();
    assert!(!exact_device_is_revoked(missing, "device_current").unwrap());
}

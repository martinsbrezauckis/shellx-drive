use chrono::Duration as ChronoDuration;
use shellx_drive_desktop_core::{DesktopAgentDisconnectContinuation, DesktopAgentDisconnectPhase};

use super::{next_retry_delay_for, Duration, Utc, AGENT_POLL_INTERVAL};

fn continuation(
    phase: DesktopAgentDisconnectPhase,
    completion_expires_at: chrono::DateTime<Utc>,
) -> DesktopAgentDisconnectContinuation {
    DesktopAgentDisconnectContinuation {
        canonical_server_origin: "https://drive.example.test".to_string(),
        command_id: "command_1".to_string(),
        lease_id: "lease_1".to_string(),
        retirement_expires_at: None,
        completion_expires_at,
        completion_event_sequence: 3,
        phase,
        retire_assertion: None,
        bound_owner_session: None,
        terminal_receipt: None,
        blocked_reason: None,
    }
}

#[test]
fn deadline_crossed_during_a_request_gets_finalization_and_bounded_retries() {
    let now = Utc::now();
    let continuation = continuation(
        DesktopAgentDisconnectPhase::Reporting,
        now - ChronoDuration::milliseconds(1),
    );
    let mut failures = 0;

    assert_eq!(
        next_retry_delay_for(&continuation, now, &mut failures),
        Some(Duration::ZERO)
    );
    for expected_failures in 2..=4 {
        assert_eq!(
            next_retry_delay_for(&continuation, now, &mut failures),
            Some(AGENT_POLL_INTERVAL)
        );
        assert_eq!(failures, expected_failures);
    }
    assert_eq!(
        next_retry_delay_for(&continuation, now, &mut failures),
        None
    );
}

#[test]
fn blocked_disposition_retries_local_finalization_after_deadline() {
    let now = Utc::now();
    let continuation = continuation(
        DesktopAgentDisconnectPhase::CompletionBlocked,
        now - ChronoDuration::minutes(1),
    );
    let mut failures = 0;

    assert_eq!(
        next_retry_delay_for(&continuation, now, &mut failures),
        Some(Duration::ZERO)
    );
    assert_eq!(
        next_retry_delay_for(&continuation, now, &mut failures),
        Some(AGENT_POLL_INTERVAL)
    );
}

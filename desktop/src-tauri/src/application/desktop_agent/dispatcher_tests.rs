use super::*;
use chrono::Duration as ChronoDuration;

#[test]
fn renewal_cadence_stays_before_a_45_second_lease_and_bounds_short_leases() {
    let now = Utc::now();
    assert_eq!(
        lease_renewal_interval(now + ChronoDuration::seconds(45), now),
        Duration::from_secs(15)
    );
    assert_eq!(
        lease_renewal_interval(now + ChronoDuration::seconds(6), now),
        Duration::from_secs(3)
    );
    assert_eq!(
        lease_renewal_interval(now - ChronoDuration::seconds(1), now),
        Duration::from_secs(1)
    );
}

#[test]
fn authority_loss_and_generic_conflicts_never_become_successful_outcomes() {
    let authorization = command_outcome_for_error(&DesktopError::Server {
        status: 401,
        message: "expired".to_string(),
    });
    assert_eq!(
        authorization.code,
        shellx_drive_desktop_core::DesktopAgentTerminalCode::AuthorizationLost
    );
    assert_eq!(
        authorization.status,
        shellx_drive_desktop_core::DesktopAgentTerminalStatus::Failed
    );
    assert!(authorization.result.is_none());

    let conflict = command_outcome_for_error(&DesktopError::Server {
        status: 409,
        message: "Drive changed this item before the update could be applied".to_string(),
    });
    assert_eq!(
        conflict.code,
        shellx_drive_desktop_core::DesktopAgentTerminalCode::NativeDispatchFailed
    );
    assert!(conflict.result.is_none());
}

#[test]
fn offline_sync_view_never_produces_a_successful_terminal_outcome() {
    let error = require_completed_sync_status("offline").expect_err("offline must block sync");
    let outcome = command_outcome_for_error(&error);

    assert_eq!(
        outcome.status,
        shellx_drive_desktop_core::DesktopAgentTerminalStatus::Failed
    );
    assert_eq!(
        outcome.code,
        shellx_drive_desktop_core::DesktopAgentTerminalCode::NativeDispatchFailed
    );
    assert!(outcome.result_code.is_none());
    assert!(outcome.result.is_none());
}

#[test]
fn only_completed_sync_view_statuses_remain_eligible_for_a_result() {
    for status in ["synced", "needs_review"] {
        require_completed_sync_status(status)
            .unwrap_or_else(|_| panic!("{status} must remain eligible for sync completion"));
    }

    for status in [
        "needs_setup",
        "needs_reconnect",
        "syncing",
        "paused",
        "offline",
        "error",
        "unknown",
    ] {
        assert!(
            require_completed_sync_status(status).is_err(),
            "{status} must not become a completed sync result"
        );
    }
}

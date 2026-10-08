use shellx_drive_desktop_core::{DesktopAgentAbandonmentReason, DesktopError};

use super::cancellation::abandonment_reason;

#[test]
fn generic_conflict_remains_a_broker_conflict() {
    assert_eq!(
        abandonment_reason(&DesktopError::Server {
            status: 409,
            message: "desktop-agent command event conflicted".to_string(),
        }),
        Some(DesktopAgentAbandonmentReason::BrokerConflict)
    );
}

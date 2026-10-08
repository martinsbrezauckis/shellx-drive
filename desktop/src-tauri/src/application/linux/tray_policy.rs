//! Small, testable Linux tray admission rules.

use shellx_drive_desktop_core::SyncStatus;

pub(super) const OPEN_REVIEWS_EVENT: &str = "shellx-drive-open-reviews";

pub(super) fn status_label(status: &str) -> &'static str {
    match status {
        "needs_setup" => "Needs setup",
        "needs_reconnect" => "Needs reconnect",
        "synced" => "Synced",
        "syncing" => "Syncing",
        "paused" => "Paused",
        "offline" => "Offline",
        "needs_review" => "Needs review",
        _ => "Error",
    }
}

pub(super) fn can_sync(
    paired: bool,
    cleanup_pending: bool,
    paused: bool,
    status: SyncStatus,
) -> bool {
    paired
        && !cleanup_pending
        && !paused
        && !matches!(
            status,
            SyncStatus::Syncing
                | SyncStatus::NeedsSetup
                | SyncStatus::NeedsReconnect
                | SyncStatus::Paused
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_sync_requires_a_paired_authenticated_nonpaused_runtime() {
        assert!(can_sync(true, false, false, SyncStatus::Synced));
        for status in [
            SyncStatus::NeedsSetup,
            SyncStatus::NeedsReconnect,
            SyncStatus::Syncing,
            SyncStatus::Paused,
        ] {
            assert!(!can_sync(true, false, false, status));
        }
        assert!(!can_sync(false, false, false, SyncStatus::Synced));
        assert!(!can_sync(true, true, false, SyncStatus::Synced));
        assert!(!can_sync(true, false, true, SyncStatus::Synced));
    }

    #[test]
    fn tray_review_event_has_the_shared_ui_contract_name() {
        assert_eq!(OPEN_REVIEWS_EVENT, "shellx-drive-open-reviews");
    }
}

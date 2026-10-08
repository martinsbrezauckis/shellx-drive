#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TraySyncRequest {
    SyncNow,
    RecheckReviews,
}

pub(super) fn tray_sync_request(id: &str) -> Option<TraySyncRequest> {
    match id {
        "sync-now" => Some(TraySyncRequest::SyncNow),
        "recheck-reviews" => Some(TraySyncRequest::RecheckReviews),
        _ => None,
    }
}

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

/// The tray must not launch a transfer when no authenticated Drive session is
/// available. Opening the window remains available so the person can reconnect.
pub(super) fn tray_sync_enabled(status: &str) -> bool {
    !matches!(
        status,
        "syncing" | "needs_setup" | "needs_reconnect" | "paused"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_recheck_event_never_routes_to_an_ordinary_sync_pass() {
        assert_eq!(
            tray_sync_request("recheck-reviews"),
            Some(TraySyncRequest::RecheckReviews)
        );
        assert_ne!(
            tray_sync_request("recheck-reviews"),
            Some(TraySyncRequest::SyncNow)
        );
    }

    #[test]
    fn tray_sync_is_disabled_until_authentication_is_available() {
        assert!(!tray_sync_enabled("needs_reconnect"));
        assert!(!tray_sync_enabled("needs_setup"));
        assert!(tray_sync_enabled("offline"));
        assert!(tray_sync_enabled("synced"));
    }
}

//! Pure Windows tray labels and enablement policy.

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

pub(super) fn tray_sync_is_enabled(
    paired: bool,
    credential_available: bool,
    cleanup_pending: bool,
    paused: bool,
    status: &str,
) -> bool {
    paired
        && credential_available
        && !cleanup_pending
        && !paused
        && !matches!(
            status,
            "syncing" | "needs_setup" | "needs_reconnect" | "paused"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_has_its_shared_tray_label() {
        assert_eq!(status_label("needs_reconnect"), "Needs reconnect");
    }

    #[test]
    fn sync_and_recheck_require_a_paired_credential() {
        assert!(!tray_sync_is_enabled(
            true,
            false,
            false,
            false,
            "needs_reconnect"
        ));
        assert!(!tray_sync_is_enabled(
            true,
            true,
            false,
            false,
            "needs_reconnect"
        ));
        assert!(!tray_sync_is_enabled(
            true,
            false,
            false,
            false,
            "needs_review"
        ));
        assert!(tray_sync_is_enabled(
            true,
            true,
            false,
            false,
            "needs_review"
        ));
    }
}

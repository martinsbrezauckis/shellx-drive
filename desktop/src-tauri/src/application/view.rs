//! Bounded browser-facing projection of non-secret desktop state.

mod projection;

use serde::Serialize;
use shellx_drive_desktop_core::ActivityEntry;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SyncLocationView {
    pub(crate) id: String,
    pub(crate) drive_location: String,
    pub(crate) local_root: String,
    pub(crate) active: bool,
    /// Root-local state remains visible even when another location is selected.
    pub(crate) sync_status: &'static str,
    pub(crate) error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopView {
    pub(crate) status: &'static str,
    /// Credential recovery keeps sync blocked while same-identity sign-in is
    /// available before a durable Disconnect begins.
    pub(crate) credential_recovery_pending: bool,
    pub(crate) app_version: &'static str,
    /// Startup could not confirm a prior human update target without reusing
    /// sync-error state.
    pub(crate) update_recovery_target_version: Option<String>,
    pub(crate) account: String,
    pub(crate) server_host: String,
    pub(crate) server_url: String,
    pub(crate) drive_location: String,
    pub(crate) local_root: String,
    pub(crate) local_usage_bytes: Option<u64>,
    pub(crate) local_usage_file_count: Option<usize>,
    pub(crate) local_usage_folder_count: Option<usize>,
    pub(crate) active_pair_id: Option<String>,
    pub(crate) sync_locations: Vec<SyncLocationView>,
    /// New-root discovery is paused; configured roots have separate current
    /// authority and may continue syncing.
    pub(crate) root_discovery_overflow: bool,
    pub(crate) last_successful_sync: Option<String>,
    pub(crate) review_count: usize,
    pub(crate) pending_remote_revocations: usize,
    /// Retained sign-in or offboarding work can exist before the first pair.
    /// This exposes the normal Disconnect action, not cleanup authorization.
    pub(crate) disconnect_available: bool,
    /// A user or broker Disconnect is cooperatively stopping a live sync;
    /// credential and device cleanup has not started yet.
    pub(crate) disconnect_requested: bool,
    pub(crate) disconnect_cleanup_pending: bool,
    pub(crate) disconnect_remote_retirement_confirmed: bool,
    /// `None` in v0.1 because the coordinator does not expose a safe,
    /// authoritative per-file transfer count.
    pub(crate) active_files: Option<usize>,
    pub(crate) reviews: Vec<shellx_drive_desktop_core::ReviewItem>,
    pub(crate) activity: Vec<ActivityEntry>,
    pub(crate) paused: bool,
    pub(crate) launch_at_login: bool,
    pub(crate) desktop_agent_enabled: bool,
    pub(crate) desktop_agent_ready: bool,
    pub(crate) error: Option<String>,
}

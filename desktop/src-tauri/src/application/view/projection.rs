//! Truthful desktop-view projection across every materialized Drive root.

use chrono::Utc;
use shellx_drive_desktop_core::{sync_pair_id, CoordinatorViewSnapshot, DisconnectCleanupIntent};

use crate::application::{
    runtime::{host_label, pair_location_label, status_code, Runtime},
    DesktopView, SyncLocationView,
};
#[cfg(test)]
mod coherence_tests;
mod policy;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod tests;
use policy::sync_location_status;
impl Runtime {
    pub(crate) fn view(&self) -> DesktopView {
        self.view_from_coordinator_snapshot(self.coordinator.view_snapshot())
    }
    fn view_from_coordinator_snapshot(&self, snapshot: CoordinatorViewSnapshot) -> DesktopView {
        let status = status_code(self.status_for_view_snapshot(&snapshot));
        let credential_recovery_pending = self.candidate_recovery_pending();
        let state = snapshot.state;
        let local_usage = self
            .local_usage_cache
            .measure_all(state.pairs().map(|pair| pair.local_root.as_path()));
        let active_pair_id = state.pair.as_ref().map(sync_pair_id);
        let disconnect_available = state.pairs().next().is_some()
            || state.active_remote_session.is_some()
            || state.pending_candidate_session.is_some()
            || !state.pending_remote_revocations.is_empty()
            || state.has_pending_disconnect_cleanup()
            || state.pending_desktop_agent_disconnect().is_some()
            || state.desktop_agent_control.enabled
            || self.session.lock().expect("session lock").is_some()
            || self
                .pending_login
                .lock()
                .expect("pending login lock")
                .is_some();
        let update_recovery_target_version = self.update_recovery_target_version();
        let sync_locations = state
            .pairs()
            .map(|pair| {
                let id = sync_pair_id(pair);
                let (review_count, error) = if active_pair_id.as_deref() == Some(id.as_str()) {
                    (state.reviews.len(), state.last_error.clone())
                } else {
                    state
                        .inactive_pairs
                        .iter()
                        .find(|profile| sync_pair_id(&profile.pair) == id)
                        .map(|profile| (profile.reviews.len(), profile.last_error.clone()))
                        .unwrap_or_default()
                };
                let sync_status = sync_location_status(
                    review_count,
                    error.as_deref(),
                    state.paused,
                    active_pair_id.as_deref() == Some(id.as_str()),
                );
                SyncLocationView {
                    active: active_pair_id.as_deref() == Some(id.as_str()),
                    id,
                    drive_location: pair_location_label(pair),
                    local_root: pair.local_root.display().to_string(),
                    sync_status,
                    error,
                }
            })
            .collect();
        let (account, server_url, drive_location, local_root) =
            if let Some(pair) = state.pair.as_ref() {
                (
                    pair.account_email.clone(),
                    pair.server_url.clone(),
                    pair_location_label(pair),
                    pair.local_root.display().to_string(),
                )
            } else {
                let (account, server_url) =
                    policy::unpaired_identity(self, &state, credential_recovery_pending)
                        .map(|session| (session.email.clone(), session.server_url.clone()))
                        .unwrap_or_default();
                (account, server_url, String::new(), String::new())
            };
        DesktopView {
            status,
            credential_recovery_pending,
            app_version: env!("CARGO_PKG_VERSION"),
            update_recovery_target_version,
            account,
            server_host: host_label(&server_url),
            server_url,
            drive_location,
            local_root,
            local_usage_bytes: local_usage.map(|usage| usage.logical_bytes),
            local_usage_file_count: local_usage.map(|usage| usage.file_count),
            local_usage_folder_count: local_usage.map(|usage| usage.folder_count),
            active_pair_id,
            sync_locations,
            root_discovery_overflow: state.root_discovery_overflow && state.pair_count() > 0,
            last_successful_sync: state.last_successful_sync.map(|time| time.to_rfc3339()),
            // Overview reviews include every configured location.
            review_count: state.pending_review_count(),
            pending_remote_revocations: state.pending_remote_revocation_count(Utc::now()),
            disconnect_available,
            disconnect_requested: snapshot.disconnect_requested,
            disconnect_cleanup_pending: state.has_pending_disconnect_cleanup(),
            disconnect_remote_retirement_confirmed: state
                .pending_disconnect_cleanup()
                .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed),
            // A serialized reservation may reconcile several roots and v0.1
            // does not track in-flight actions. Expose absence, not a fake zero.
            active_files: None,
            paused: state.paused,
            launch_at_login: state.launch_at_login,
            desktop_agent_enabled: state.desktop_agent_control.enabled,
            desktop_agent_ready: state.desktop_agent_control.enabled
                && state.desktop_agent_control.device_id.is_some()
                && !state.has_pending_disconnect_cleanup()
                && !self.candidate_recovery_pending(),
            error: state.aggregate_error(),
            reviews: state.reviews,
            activity: state.activity,
        }
    }
}

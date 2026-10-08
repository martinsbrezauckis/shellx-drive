//! Every-root terminal precedence shared by native reconciliation adapters.

use std::path::PathBuf;

use chrono::Utc;
use shellx_drive_desktop_core::{
    ActivityEntry, DesktopError, DesktopState, Result as CoreResult, SyncRun,
};

#[cfg(test)]
mod conformance_tests;
pub(crate) mod failure;
#[cfg(test)]
mod failure_tests;
pub(crate) mod session;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod tests;

#[derive(Default)]
pub(crate) struct SyncCycleTerminal {
    transient_error: Option<DesktopError>,
}

impl SyncCycleTerminal {
    pub(crate) fn record_budget_exhaustion(&mut self, run: &mut SyncRun, error: DesktopError) {
        run.record_active_error(error.to_string());
        run.append_active_activity(ActivityEntry {
            at: Utc::now(),
            direction: "Drive".to_string(),
            relative_path: PathBuf::new(),
            result: "The sync cycle reached its resource limit; remaining locations were deferred."
                .to_string(),
        });
    }

    pub(crate) fn record_root_failure(&mut self, run: &mut SyncRun, error: DesktopError) {
        if is_transient_server_unavailable(&error) {
            self.transient_error.get_or_insert(error);
            run.append_active_activity(ActivityEntry {
                at: Utc::now(),
                direction: "Drive".to_string(),
                relative_path: PathBuf::new(),
                result: "Drive is temporarily unavailable; other locations continued and retry remains available."
                    .to_string(),
            });
        } else {
            run.record_active_error(error.to_string());
            run.append_active_activity(ActivityEntry {
                at: Utc::now(),
                direction: "Drive".to_string(),
                relative_path: PathBuf::new(),
                result: "This Drive location did not finish syncing; other locations continued."
                    .to_string(),
            });
        }
    }

    pub(crate) fn finish(self, final_state: &DesktopState) -> CoreResult<()> {
        // A transient failure must never mask a review or permanent failure
        // retained on another configured location.
        if final_state.has_any_reviews() || final_state.has_any_pair_error() {
            Ok(())
        } else {
            self.transient_error.map_or(Ok(()), Err)
        }
    }
}

pub(crate) fn is_transient_server_unavailable(error: &DesktopError) -> bool {
    matches!(
        error,
        DesktopError::Http(_)
            | DesktopError::Server {
                status: 500..=599,
                ..
            }
    )
}

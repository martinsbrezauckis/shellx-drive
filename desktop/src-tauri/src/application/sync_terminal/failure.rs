//! Persisted terminal policy for failures before or during native sync.

use std::path::PathBuf;

use chrono::Utc;
use shellx_drive_desktop_core::{ActivityEntry, DesktopError, Result as CoreResult};

use super::is_transient_server_unavailable;
use crate::application::Runtime;

pub(crate) fn is_sync_admission_error(error: &DesktopError) -> bool {
    matches!(
        error,
        DesktopError::SyncAlreadyRunning
            | DesktopError::SyncCancelledForDisconnect
            | DesktopError::NeedsReconnect
    )
}

pub(crate) enum TerminalFailure {
    Admission(DesktopError),
    Offline,
    Persistent(DesktopError),
}

pub(crate) fn persist_terminal_failure(
    runtime: &Runtime,
    error: DesktopError,
) -> CoreResult<TerminalFailure> {
    if is_sync_admission_error(&error) {
        return Ok(TerminalFailure::Admission(error));
    }
    if is_transient_server_unavailable(&error) {
        runtime.coordinator.set_offline(true);
        runtime.coordinator.append_activity(ActivityEntry {
            at: Utc::now(),
            direction: "Drive".to_string(),
            relative_path: PathBuf::new(),
            result: "Offline; retry remains available.".to_string(),
        });
        runtime.save()?;
        return Ok(TerminalFailure::Offline);
    }
    runtime.coordinator.record_error(error.to_string());
    runtime.save()?;
    Ok(TerminalFailure::Persistent(error))
}

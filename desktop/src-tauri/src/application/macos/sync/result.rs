//! Common terminal projection for a macOS sync or review recheck.

use super::*;
use crate::application::sync_terminal::failure::{persist_terminal_failure, TerminalFailure};
#[cfg(test)]
use crate::application::sync_terminal::is_transient_server_unavailable;

pub(super) fn settle_root_refresh_failure(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    error: DesktopError,
) -> Result<DesktopView, String> {
    if matches!(error, DesktopError::SyncAlreadyRunning) {
        return Err(macos_error(error));
    }
    settle_result(app, runtime, Err(error))
}

pub(super) fn settle_result(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    result: CoreResult<()>,
) -> Result<DesktopView, String> {
    runtime.local_usage_cache.invalidate();
    if let Err(error) = result {
        match persist_terminal_failure(runtime, error).map_err(macos_error)? {
            TerminalFailure::Admission(DesktopError::NeedsReconnect) => {
                shell::update_tray(app, runtime);
                return Ok(runtime.view());
            }
            TerminalFailure::Admission(error) => return Err(macos_error(error)),
            TerminalFailure::Offline => {
                shell::update_tray(app, runtime);
                return Ok(runtime.view());
            }
            TerminalFailure::Persistent(error) => {
                shell::update_tray(app, runtime);
                shell::notify_actionable(app, runtime, true);
                return Err(macos_error(error));
            }
        }
    }
    shell::update_tray(app, runtime);
    shell::notify_actionable(app, runtime, true);
    Ok(runtime.view())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_outage_is_offline_but_access_removal_and_local_failures_are_not() {
        assert!(is_transient_server_unavailable(&DesktopError::Server {
            status: 503,
            message: "unavailable".to_string(),
        }));
        assert!(!is_transient_server_unavailable(&DesktopError::Server {
            status: 403,
            message: "revoked".to_string(),
        }));
        assert!(!is_transient_server_unavailable(&DesktopError::UnsafePath(
            "local path changed".to_string(),
        )));
    }

    #[test]
    fn refused_loopback_transport_is_offline() {
        let client = DriveHttpClient::new("https://127.0.0.1:0").expect("valid test origin");
        let error = tauri::async_runtime::block_on(client.validate_server())
            .expect_err("closed loopback port must refuse the request");
        assert!(is_transient_server_unavailable(&error));
    }
}

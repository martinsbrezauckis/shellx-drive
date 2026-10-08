//! Startup-only continuation of an already confirmed macOS Disconnect.

use shellx_drive_desktop_core::{
    DesktopState, DisconnectCleanupIntent, Result as CoreResult, StateStore,
};

use super::offboarding::complete_local_cleanup;

/// Never retry remote retirement at startup.  Once it was durably confirmed,
/// only the exact local Keychain, marker, and owned LaunchAgent cleanup may
/// resume.
pub(super) fn resume_macos_disconnect_cleanup(
    store: &StateStore,
    state: &mut DesktopState,
) -> CoreResult<()> {
    if state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
        && state.pair.is_none()
    {
        complete_local_cleanup(store, state)?;
    }
    Ok(())
}

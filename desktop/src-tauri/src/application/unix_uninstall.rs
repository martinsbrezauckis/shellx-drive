//! Final Unix package-removal check after interactive Disconnect.
//!
//! A command-line flag is not an uninstall authorization. The interactive
//! desktop must first retire remote sessions and the device, remove the exact
//! credential slots and pair markers, and finish its durable cleanup journal.
//! This mode only verifies that outcome and removes owned autostart wiring.

use shellx_drive_desktop_core::{
    default_state_path, uninstall_credential_registry_empty, DesktopError, Result as CoreResult,
    StateStore,
};

pub(crate) mod remote;

/// Package scripts may call this from the installed binary. The instance
/// lease is held through both credential inventory checks and autostart removal.
pub(crate) fn run_uninstall_cleanup_with_lease() -> i32 {
    let _lease = match crate::platform::unix::instance::UnixDesktopInstanceLease::acquire() {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            eprintln!("Close ShellX Drive before uninstall cleanup can run.");
            return 1;
        }
        Err(_) => {
            eprintln!("ShellX Drive could not safely acquire its uninstall cleanup lease.");
            return 1;
        }
    };
    match verify_disconnected_and_remove_autostart() {
        Ok(()) => 0,
        Err(_) => {
            eprintln!(
                "Open ShellX Drive, finish Disconnect and any pending recovery, then retry uninstall. Synced files and saved credentials were kept."
            );
            1
        }
    }
}

fn verify_disconnected_and_remove_autostart() -> CoreResult<()> {
    let store = StateStore::new(default_state_path()?);
    let mut state = store.load()?;
    if !state.uninstall_cleanup_ready() || !uninstall_credential_registry_empty()? {
        return Err(DesktopError::InvalidState(
            "interactive Disconnect must finish before uninstall".to_string(),
        ));
    }
    crate::platform::unix::remove_owned_launch_at_login()?;
    if state.launch_at_login {
        state.launch_at_login = false;
        store.save(&state)?;
    }
    Ok(())
}

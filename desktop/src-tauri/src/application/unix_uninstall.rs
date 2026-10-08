//! Final Unix package-removal check after interactive Disconnect.
//!
//! A command-line flag is not an uninstall authorization. The interactive
//! desktop must first retire remote sessions and the device, remove the exact
//! credential slots and pair markers, and finish its durable cleanup journal.
//! This mode only verifies that outcome and removes owned autostart wiring.

use shellx_drive_desktop_core::{
    default_state_path, uninstall_credential_registry_empty, DesktopError, DesktopState,
    Result as CoreResult, StateStore,
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
    let state = store.load()?;
    let primary = std::sync::Arc::new(read_only_runtime(store, state)?);
    let manager =
        super::ConnectionManager::load_without_credential_migration(primary, read_only_runtime)?;
    if manager.has_unavailable_connections()
        || manager
            .all_runtimes()
            .iter()
            .any(|runtime| !runtime.coordinator.snapshot().uninstall_cleanup_ready())
        || !uninstall_credential_registry_empty()?
    {
        return Err(DesktopError::InvalidState(
            "Remove every connection and finish pending recovery before uninstalling Drive.".into(),
        ));
    }
    crate::platform::unix::remove_owned_launch_at_login()?;
    let preferences = manager.preferences();
    manager.save_preferences(
        preferences.theme,
        false,
        preferences.default_sync_interval_seconds,
    )?;
    Ok(())
}

fn read_only_runtime(store: StateStore, state: DesktopState) -> CoreResult<super::Runtime> {
    Ok(super::Runtime::from_loaded_state(
        Box::new(crate::platform::unix::UnixPlatformServices::default()),
        store,
        state,
    ))
}

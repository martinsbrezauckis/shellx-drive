//! Final Windows package-removal check after interactive Disconnect.

use super::{startup::set_windows_startup, *};

/// The NSIS hook holds the process lease while this checks the durable state
/// and all four exact credential namespaces. No bearer is read or retired by
/// this command-line path. The user must finish Disconnect in the app first.
pub(super) fn verify_disconnected_and_remove_startup() -> CoreResult<()> {
    let store = StateStore::new(default_state_path()?);
    let state = store.load()?;
    let primary = Arc::new(uninstall_runtime(store, state)?);
    let manager = ConnectionManager::load_without_credential_migration(primary, uninstall_runtime)?;
    if manager.has_unavailable_connections() || manager.all_runtimes().iter().any(|runtime| !runtime.coordinator.snapshot().uninstall_cleanup_ready())
        || !WindowsCredentialStore::service_account_keys()?.is_empty()
        || !PendingWindowsCredentialStore::service_account_keys()?.is_empty()
        || !shellx_drive_desktop_core::WindowsDesktopAgentCredentialStore::service_account_keys()?
            .is_empty()
        || !shellx_drive_desktop_core::WindowsDesktopAgentDisconnectCredentialStore::service_account_keys()?
            .is_empty()
    {
        return Err(DesktopError::InvalidState(
            "interactive Disconnect must finish before uninstall".to_string(),
        ));
    }
    set_windows_startup(false)
}

fn uninstall_runtime(store: StateStore, state: DesktopState) -> CoreResult<Runtime> {
    // The package-removal path inspects durable state only. Do not invoke the
    // normal runtime factory, which may resume credential or marker cleanup.
    Ok(Runtime::from_loaded_state(
        Box::new(crate::platform::windows::WindowsPlatformServices::default()),
        store,
        state,
    ))
}

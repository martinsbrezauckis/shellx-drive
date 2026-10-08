//! App preferences and explicit, scoped connection lifecycle commands.

use super::{connections::ConnectionsView, ConnectionManager, Runtime};

static PREFERENCE_PUBLICATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
use serde::Serialize;
use shellx_drive_desktop_core::{DesktopError, Result as CoreResult};
use std::sync::Arc;
use tauri::{AppHandle, State};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BeginConnectionReply {
    connection_id: String,
}

#[tauri::command]
pub(crate) fn get_connections_view(manager: State<'_, ConnectionManager>) -> ConnectionsView {
    manager.view()
}

#[tauri::command]
pub(crate) fn begin_connection(
    manager: State<'_, ConnectionManager>,
    name: String,
) -> Result<BeginConnectionReply, String> {
    Ok(BeginConnectionReply {
        connection_id: manager.begin_connection(name).map_err(present_error)?,
    })
}

#[tauri::command]
pub(crate) fn complete_connection(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: String,
) -> Result<ConnectionsView, String> {
    let runtime = manager
        .resolve(Some(&connection_id))
        .map_err(present_error)?;
    let view = manager
        .complete_connection(&connection_id)
        .map_err(present_error)?;
    start_connection_polling(&app, &runtime);
    super::desktop_agent::start_polling(&app, &runtime);
    Ok(view)
}

#[tauri::command]
pub(crate) fn save_connection(
    manager: State<'_, ConnectionManager>,
    connection_id: String,
    name: String,
    interval_seconds: Option<u64>,
) -> Result<ConnectionsView, String> {
    manager
        .save_connection(&connection_id, name, interval_seconds)
        .map_err(present_error)
}

#[tauri::command]
pub(crate) fn save_app_preferences(
    manager: State<'_, ConnectionManager>,
    theme: String,
    launch_at_login: bool,
    default_sync_interval_seconds: u64,
) -> Result<ConnectionsView, String> {
    persist_app_preferences(
        &manager,
        theme,
        launch_at_login,
        default_sync_interval_seconds,
    )
    .map_err(present_error)
}

pub(crate) fn persist_app_preferences(
    manager: &ConnectionManager,
    theme: String,
    launch_at_login: bool,
    default_sync_interval_seconds: u64,
) -> CoreResult<ConnectionsView> {
    let _publication = PREFERENCE_PUBLICATION
        .lock()
        .expect("app preferences publication lock");
    persist_preferences_locked(
        manager,
        theme,
        launch_at_login,
        default_sync_interval_seconds,
    )
}

pub(crate) fn persist_launch_preference(
    manager: &ConnectionManager,
    enabled: bool,
) -> CoreResult<ConnectionsView> {
    let _publication = PREFERENCE_PUBLICATION
        .lock()
        .expect("app preferences publication lock");
    let previous = manager.preferences();
    persist_preferences_locked(
        manager,
        previous.theme,
        enabled,
        previous.default_sync_interval_seconds,
    )
}

fn persist_preferences_locked(
    manager: &ConnectionManager,
    theme: String,
    launch_at_login: bool,
    default_sync_interval_seconds: u64,
) -> CoreResult<ConnectionsView> {
    manager.ensure_mutation_allowed()?;
    let previous = manager.preferences();
    let primary = manager.app_service_runtime();
    primary.platform.set_launch_at_login(launch_at_login)?;
    match manager.save_preferences(theme, launch_at_login, default_sync_interval_seconds) {
        Ok(view) => Ok(view),
        Err(error) => {
            primary.platform.set_launch_at_login(previous.launch_at_login).map_err(|rollback| DesktopError::InvalidState(format!(
                "App preferences were not saved and launch-at-login needs repair: {error}; {rollback}"
            )))?;
            Err(error)
        }
    }
}

/// Closing a sign-in form cancels only its transient login continuation.
#[tauri::command]
pub(crate) async fn cancel_login(
    manager: State<'_, ConnectionManager>,
    connection_id: String,
) -> Result<(), String> {
    let runtime = manager
        .resolve(Some(&connection_id))
        .map_err(present_error)?;
    let _publication = runtime.auth_publication.lock().await;
    runtime
        .auth_offboarding
        .admit_login()
        .map_err(present_error)?;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    Ok(())
}

#[tauri::command]
pub(crate) async fn cancel_connection(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: String,
) -> Result<ConnectionsView, String> {
    retire_connection(&app, &manager, &connection_id, true)
        .await
        .map_err(present_error)
}

#[tauri::command]
pub(crate) async fn remove_connection(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: String,
) -> Result<ConnectionsView, String> {
    retire_connection(&app, &manager, &connection_id, false)
        .await
        .map_err(present_error)
}

async fn retire_connection(
    app: &AppHandle,
    manager: &ConnectionManager,
    id: &str,
    only_preparing: bool,
) -> CoreResult<ConnectionsView> {
    let runtime = manager.resolve(Some(id))?;
    if only_preparing {
        manager.mark_removing_if_preparing(id)?;
    } else {
        manager.mark_removing(id)?;
    }
    *runtime.pending_login.lock().expect("pending login lock") = None;
    #[cfg(target_os = "windows")]
    super::windows::disconnect_cleanup::disconnect_impl(app, &runtime)
        .await
        .map_err(DesktopError::InvalidState)?;
    #[cfg(target_os = "linux")]
    super::linux::disconnect::disconnect_impl(app, &runtime)
        .await
        .map_err(DesktopError::InvalidState)?;
    #[cfg(target_os = "macos")]
    super::macos::offboarding::disconnect_impl(app, &runtime)
        .await
        .map_err(DesktopError::InvalidState)?;
    let state = runtime.coordinator.snapshot();
    if state.pair.is_some()
        || state.has_pending_disconnect_cleanup()
        || state.pending_desktop_agent_disconnect().is_some()
    {
        return Err(DesktopError::InvalidState("Connection removal is still finishing. Retry Remove server; local files stay in their folder.".into()));
    }
    manager.finish_removal(id)
}

#[tauri::command]
pub(crate) async fn replace_connection_folder(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: String,
    local_root: String,
    confirmed: bool,
) -> Result<ConnectionsView, String> {
    if !confirmed {
        return Err("Confirm that files stay in the current folder and Drive starts a fresh sync in the new folder.".into());
    }
    manager.ensure_mutation_allowed().map_err(present_error)?;
    let runtime = manager
        .resolve(Some(&connection_id))
        .map_err(present_error)?;
    #[cfg(target_os = "windows")]
    super::windows::root_sync::replace_folder_impl(&app, &runtime, &manager, local_root).await?;
    #[cfg(target_os = "linux")]
    super::linux::roots::replace_folder_impl(&app, &runtime, &manager, local_root).await?;
    #[cfg(target_os = "macos")]
    super::macos::pairing::replace_folder_impl(&app, &runtime, &manager, local_root).await?;
    // Refresh persisted ownership after successful native publication.
    manager
        .complete_connection(&connection_id)
        .map_err(present_error)
}

pub(crate) fn start_connection_polling(app: &AppHandle, runtime: &Arc<Runtime>) {
    #[cfg(target_os = "windows")]
    super::windows::start_connection_polling(app, runtime);
    #[cfg(target_os = "linux")]
    super::linux::sync::start_polling(app, runtime);
    #[cfg(target_os = "macos")]
    super::macos::sync::start_polling(app, runtime);
}

fn present_error(error: DesktopError) -> String {
    error.to_string()
}

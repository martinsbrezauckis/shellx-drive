//! Explicit addition beneath the existing Drive base.

use tauri::{AppHandle, State};

use crate::application::{connections::ConnectionManager, DesktopView};

#[tauri::command]
pub(super) async fn add_root(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    workspace_id: String,
    remote_root_id: Option<String>,
    sync_root_id: String,
) -> Result<DesktopView, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(|error| error.to_string())?;
    let base = runtime
        .coordinator
        .snapshot()
        .sync_root_base
        .ok_or_else(|| "Connect a first Drive root before adding another.".to_string())?;
    super::roots::start_pair_impl(
        &app,
        &runtime,
        &manager,
        workspace_id,
        remote_root_id,
        sync_root_id,
        base.to_string_lossy().into_owned(),
    )
    .await
}

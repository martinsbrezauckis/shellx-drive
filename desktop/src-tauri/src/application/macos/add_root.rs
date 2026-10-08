//! Explicit addition beneath the existing Drive base.

use tauri::{AppHandle, State};

use crate::application::{ConnectionManager, DesktopView};

#[tauri::command]
pub(super) async fn add_root(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    workspace_id: String,
    remote_root_id: Option<String>,
    sync_root_id: String,
) -> Result<DesktopView, String> {
    manager
        .ensure_mutation_allowed()
        .map_err(super::macos_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(super::macos_error)?;
    let base = runtime
        .coordinator
        .snapshot()
        .sync_root_base
        .ok_or_else(|| "Connect a first Drive root before adding another.".to_string())?;
    super::pairing::start_pair_impl(
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

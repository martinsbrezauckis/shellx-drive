//! Explicit addition beneath the existing Drive base.

use tauri::{AppHandle, State};

use crate::application::{DesktopView, Runtime};

#[tauri::command]
pub(super) async fn add_root(
    app: AppHandle,
    runtime: State<'_, Runtime>,
    workspace_id: String,
    remote_root_id: Option<String>,
    sync_root_id: String,
) -> Result<DesktopView, String> {
    let base = runtime
        .coordinator
        .snapshot()
        .sync_root_base
        .ok_or_else(|| "Connect a first Drive root before adding another.".to_string())?;
    super::pairing::start_pair(
        app,
        runtime,
        workspace_id,
        remote_root_id,
        sync_root_id,
        base.to_string_lossy().into_owned(),
    )
    .await
}

use super::*;

pub(in crate::application::macos) async fn validate_connection_folders(
    app: &tauri::AppHandle,
    runtime: &Runtime,
) -> CoreResult<()> {
    let manager = app.state::<ConnectionManager>();
    let id = manager.id_for_runtime(runtime).ok_or_else(|| {
        DesktopError::InvalidState("Drive connection is no longer registered.".to_string())
    })?;
    let _admission = manager.admission.lock().await;
    let state = runtime.coordinator.snapshot();
    if let Some(base) = state.sync_root_base.as_ref() {
        manager.validate_existing_connection_folder(&id, base)?;
    }
    for pair in state.pairs() {
        manager.validate_existing_connection_folder(&id, &pair.local_root)?;
    }
    Ok(())
}

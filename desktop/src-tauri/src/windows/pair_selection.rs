//! Durable selection of the one sync location served by the active engine.

use super::*;

#[tauri::command]
pub(super) async fn select_pair(
    app: tauri::AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    pair_id: String,
) -> Result<DesktopView, String> {
    manager.ensure_mutation_allowed().map_err(user_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(user_error)?;
    select_pair_impl(&app, &runtime, pair_id).await
}

pub(crate) async fn select_pair_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    pair_id: String,
) -> Result<DesktopView, String> {
    app.state::<ConnectionManager>()
        .ensure_mutation_allowed()
        .map_err(user_error)?;
    runtime
        .require_candidate_recovery_complete()
        .map_err(user_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(user_error)?;
    let _auth_publication = runtime.auth_publication.lock().await;
    let mut operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .map_err(user_error)?;
    let mut candidate = runtime.coordinator.snapshot();
    let selected_root = candidate
        .pairs()
        .find(|pair| sync_pair_id(pair) == pair_id.trim())
        .map(|pair| pair.local_root.clone())
        .ok_or_else(|| {
            user_error(DesktopError::InvalidState(
                "unknown Drive location".to_string(),
            ))
        })?;
    let _pair_root_guard =
        guard_configured_pair_roots(&candidate, &selected_root).map_err(user_error)?;
    if candidate
        .activate_pair(pair_id.trim())
        .map_err(user_error)?
    {
        runtime.store.save(&candidate).map_err(user_error)?;
    }
    let selected = candidate
        .pair
        .as_ref()
        .map(|pair| SessionIdentity::new(pair.server_url.clone(), pair.account_email.clone()));
    operation.finish_state(candidate);
    *runtime.session.lock().expect("session lock") = selected;
    invalidate_pending_confirmation(runtime);
    update_tray(app, runtime);
    start_polling(app, runtime);
    Ok(runtime.view())
}

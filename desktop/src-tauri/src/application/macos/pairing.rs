//! Authoritative root discovery, safe local materialization, and location
//! selection for macOS.

use std::path::PathBuf;

use chrono::Utc;
use shellx_drive_desktop_core::{
    converge_sync_roots, ensure_empty_local_root, plan_local_root_locations,
    plan_selected_root_location, sync_pair_id, DesktopState, DriveHttpClient, PairMarker, SyncPair,
    SyncRoot,
};
use tauri::State;

use super::*;
use crate::{
    application::sync_terminal::session::admit_user_session_response,
    session_identity::SessionIdentity,
};

#[tauri::command]
pub(super) async fn start_pair(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
    workspace_id: String,
    remote_root_id: Option<String>,
    sync_root_id: String,
    local_root: String,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(macos_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(macos_error)?;
    let pairing_generation = runtime
        .auth_offboarding
        .admit_login()
        .map_err(macos_error)?;
    let base = absolute_existing_directory(&local_root)?;
    let session = runtime.current_session().map_err(macos_error)?;
    let token = runtime.current_token(&session).map_err(macos_error)?;
    let client = DriveHttpClient::new(&session.server_url).map_err(macos_error)?;
    let selected = admit_user_session_response(
        &runtime,
        &session,
        &token,
        client
            .revalidate_selected_sync_root(
                &token,
                sync_root_id.trim(),
                workspace_id.trim(),
                remote_root_id.as_deref(),
            )
            .await,
    )
    .await
    .map_err(macos_error)?;
    // This is the final authority read for the root the person selected. An
    // item grant never falls back to a workspace-wide manifest.
    let selected_manifest = admit_user_session_response(
        &runtime,
        &session,
        &token,
        client.sync_root_manifest(&token, &selected).await,
    )
    .await
    .map_err(macos_error)?;
    let roots = vec![selected_manifest.root.clone()];

    let _publication = runtime.auth_publication.lock().await;
    if !runtime.auth_offboarding.may_publish(pairing_generation) {
        return Err("Pairing was canceled by a newer sign-in or Disconnect.".to_string());
    }
    runtime
        .require_captured_setup_session_during_publication(&session, &token)
        .map_err(macos_error)?;
    let mut operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .map_err(macos_error)?;
    let current = runtime.coordinator.snapshot();
    let was_first_pair = current.pair_count() == 0;
    if let Some(existing) = current.sync_root_base.as_ref() {
        if existing != &base {
            return Err(
                "All accessible Drive locations use the existing local Drive folder. Disconnect this PC before choosing another folder."
                    .to_string(),
            );
        }
    } else {
        ensure_empty_local_root(&base).map_err(macos_error)?;
    }

    let mut candidate = current;
    candidate.sync_root_base = Some(base.clone());
    candidate
        .record_selected_sync_root(&roots[0])
        .map_err(macos_error)?;
    let created = materialize_roots(
        &mut candidate,
        &roots,
        &session,
        client.normalized_url(),
        &base,
    )
    .map_err(macos_error)?;
    let selected_pair_id = candidate
        .pairs()
        .find(|pair| {
            pair.workspace_id == selected_manifest.root.workspace_id
                && pair.remote_root_id == selected_manifest.root.root_file_id
        })
        .map(sync_pair_id)
        .ok_or_else(|| "The selected Drive root could not be materialized safely.".to_string())?;
    candidate
        .activate_pair(&selected_pair_id)
        .map_err(macos_error)?;
    if was_first_pair {
        candidate.launch_at_login = false;
    }
    if let Err(error) = runtime.store.save(&candidate) {
        rollback_created_markers(&created);
        return Err(macos_error(error));
    }
    operation
        .publish_persisted_state(candidate.clone())
        .map_err(macos_error)?;
    invalidate_pending_confirmation(&runtime);
    if !was_first_pair {
        operation.finish_state(candidate);
        drop(_publication);
        shell::update_tray(&app, &runtime);
        return sync::sync_now_impl(&app, &runtime).await;
    }
    if !enable_launch_at_login_after_pair(&runtime, &mut candidate) {
        sync::stop_polling(&runtime);
        operation.finish_state(candidate);
        shell::update_tray(&app, &runtime);
        return Ok(runtime.view());
    }
    operation.finish_state(candidate);
    drop(_publication);
    shell::update_tray(&app, &runtime);
    sync::start_polling(&app, &runtime);
    sync::sync_now_impl(&app, &runtime).await
}

/// Enable the paired desktop's startup entry only when its enabled state can
/// be persisted. A repair condition must remain visible instead of starting a
/// sync that could replace it with a successful status.
pub(super) fn enable_launch_at_login_after_pair(
    runtime: &Runtime,
    candidate: &mut DesktopState,
) -> bool {
    if let Err(error) = runtime.platform.set_launch_at_login(true) {
        candidate.last_error = Some(format!(
            "Drive locations were paired, but macOS launch-at-login could not be enabled: {error}"
        ));
        let _ = runtime.store.save(candidate);
        return false;
    }
    candidate.launch_at_login = true;
    if let Err(error) = runtime.store.save(candidate) {
        let rollback = runtime.platform.set_launch_at_login(false);
        candidate.launch_at_login = false;
        candidate.last_error = Some(match rollback {
            Ok(()) => format!(
                "Drive locations were paired, but the macOS launch-at-login preference could not be saved: {error}"
            ),
            Err(rollback_error) => format!(
                "Drive locations were paired, but macOS launch-at-login needs repair after persistence and rollback failures: {error}; {rollback_error}"
            ),
        });
        let _ = runtime.store.save(candidate);
        return false;
    }
    true
}

/// Refresh only configured root authority. Newly available locations require
/// an explicit picker choice; refresh never creates local content.
pub(crate) async fn refresh_authorized_roots(runtime: &Runtime) -> CoreResult<()> {
    // Root discovery can materialize local folders and markers. A pending
    // Disconnect journal is the exact cleanup authority and must win first.
    runtime.ensure_disconnect_cleanup_complete()?;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let session = runtime.current_session()?;
    let token = runtime.current_token(&session)?;
    let client = DriveHttpClient::new(&session.server_url)?;
    let mut candidate = runtime.coordinator.snapshot();
    let (discovered, overflow) = crate::application::root_discovery::discover_for_sync_refresh(
        runtime, &session, &token, &client, &candidate,
    )
    .await?;
    candidate.root_discovery_overflow = overflow;
    let Some(base) = candidate.sync_root_base.clone() else {
        operation.finish_state(candidate);
        return Ok(());
    };
    let created = match materialize_roots(
        &mut candidate,
        &discovered,
        &session,
        client.normalized_url(),
        &base,
    ) {
        Ok(created) => created,
        Err(error) => return Err(error),
    };
    if let Err(error) = candidate.reconcile_sync_roots(&discovered, Utc::now()) {
        rollback_created_markers(&created);
        return Err(error);
    }
    if let Err(error) = runtime.store.save(&candidate) {
        rollback_created_markers(&created);
        return Err(error);
    }
    operation.finish_state(candidate);
    Ok(())
}

#[tauri::command]
pub(super) async fn select_pair(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
    pair_id: String,
) -> Result<DesktopView, String> {
    select_pair_impl(&app, &runtime, pair_id).await
}

pub(crate) async fn select_pair_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    pair_id: String,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(macos_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(macos_error)?;
    let _publication = runtime.auth_publication.lock().await;
    let mut operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .map_err(macos_error)?;
    let mut candidate = runtime.coordinator.snapshot();
    let selected = candidate
        .pairs()
        .find(|pair| sync_pair_id(pair) == pair_id.trim())
        .cloned()
        .ok_or_else(|| "That Drive location is no longer configured.".to_string())?;
    let expected = selected.local_root_identity.as_ref().ok_or_else(|| {
        "This Drive location has no macOS root identity. Pair the location again.".to_string()
    })?;
    crate::platform::unix::filesystem::UnixRootGuard::acquire(&selected.local_root, Some(expected))
        .map_err(macos_error)?
        .require_exact_pair_marker(&PairMarker::from(&selected))
        .map_err(macos_error)?;
    if candidate
        .activate_pair(pair_id.trim())
        .map_err(macos_error)?
    {
        runtime.store.save(&candidate).map_err(macos_error)?;
    }
    *runtime.session.lock().expect("session lock") = Some(SessionIdentity::new(
        selected.server_url,
        selected.account_email,
    ));
    operation.finish_state(candidate);
    invalidate_pending_confirmation(runtime);
    shell::update_tray(app, runtime);
    sync::start_polling(app, runtime);
    Ok(runtime.view())
}

fn materialize_roots(
    state: &mut shellx_drive_desktop_core::DesktopState,
    discovered: &[SyncRoot],
    session: &SessionIdentity,
    server_url: &str,
    base: &std::path::Path,
) -> CoreResult<Vec<SyncPair>> {
    let roots = converge_sync_roots(discovered)?;
    let base_guard = crate::platform::unix::filesystem::UnixRootGuard::acquire(base, None)?;
    let mut created = Vec::new();
    let locations = if roots.len() == 1 {
        vec![plan_selected_root_location(state, &roots[0], base)?]
    } else {
        plan_local_root_locations(&roots)?
    };
    for location in locations {
        let root = roots
            .iter()
            .find(|root| root.id == location.root_id)
            .expect("location plan returns an existing root");
        if state.pairs().any(|pair| {
            pair.workspace_id == root.workspace_id && pair.remote_root_id == root.root_file_id
        }) {
            continue;
        }
        let local_root = base.join(&location.relative_path);
        let root_guard = base_guard.ensure_child_root(&location.relative_path)?;
        root_guard.ensure_empty_root()?;
        let pair = SyncPair {
            server_url: server_url.to_string(),
            account_email: session.email.clone(),
            workspace_id: root.workspace_id.clone(),
            workspace_name: root.label.clone(),
            remote_root_id: root.root_file_id.clone(),
            remote_root_name: root.root_file_id.as_ref().map(|_| root.label.clone()),
            local_root: local_root.clone(),
            local_root_identity: Some(root_guard.identity().clone()),
        };
        base_guard.write_or_recognize_child_pair_marker(
            &location.relative_path,
            &root_guard,
            &PairMarker::from(&pair),
        )?;
        if let Err(error) = state
            .configure_pair(pair.clone())
            .and_then(|()| state.record_sync_root(&pair, root.clone()))
        {
            let _ = root_guard.remove_exact_pair_marker(&PairMarker::from(&pair));
            rollback_created_markers(&created);
            return Err(error);
        }
        created.push(pair);
    }
    Ok(created)
}

fn rollback_created_markers(created: &[SyncPair]) {
    for pair in created.iter().rev() {
        if let Ok(guard) = crate::platform::unix::filesystem::UnixRootGuard::acquire(
            &pair.local_root,
            pair.local_root_identity.as_ref(),
        ) {
            let _ = guard.remove_exact_pair_marker(&PairMarker::from(pair));
        }
    }
}

fn absolute_existing_directory(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value.trim());
    if !path.is_absolute() || !path.is_dir() {
        return Err("Choose an existing empty folder with the native folder picker.".to_string());
    }
    Ok(path)
}

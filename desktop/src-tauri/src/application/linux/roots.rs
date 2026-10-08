//! Linux root discovery, exact marker binding, and local materialization.
//!
//! The webview only supplies an opaque root subject selected from server
//! discovery and a directory returned by the native picker. Every local
//! directory and marker change below that selected directory goes through the
//! Unix descriptor guard; no Tauri command turns a text path into a mutation.

use std::path::{Path, PathBuf};

use chrono::Utc;
use shellx_drive_desktop_core::{
    converge_sync_roots, ensure_empty_local_root, plan_local_root_locations,
    plan_selected_root_location, sync_pair_id, DesktopError, DesktopState, DriveHttpClient,
    PairMarker, PairMarkerDisposition, Result as CoreResult, SyncPair, SyncRoot,
};
use tauri::{AppHandle, State};

use crate::{
    application::{
        invalidate_pending_confirmation,
        sync_terminal::session::{
            admit_user_session_response, admit_user_session_response_during_publication,
        },
        DesktopView, Runtime,
    },
    platform::unix::filesystem::UnixRootGuard,
    session_identity::SessionIdentity,
};

use super::{shell::update_tray, sync};

/// Refresh root authority without changing the native-picked base directory.
pub(crate) async fn refresh_authorized_roots(runtime: &Runtime) -> CoreResult<()> {
    runtime.require_candidate_recovery_complete()?;
    // Root refresh must not expand a durable Disconnect cleanup journal.
    runtime.ensure_disconnect_cleanup_complete()?;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let current = runtime.coordinator.snapshot();
    let refreshed = async {
        let session = runtime.current_session()?;
        let token = runtime.current_token(&session)?;
        let client = DriveHttpClient::new(&session.server_url)?;
        let (roots, overflow) = crate::application::root_discovery::discover_for_sync_refresh(
            runtime, &session, &token, &client, &current,
        )
        .await?;
        let mut candidate = current.clone();
        candidate.root_discovery_overflow = overflow;
        let existing_base = candidate.sync_root_base.clone();
        let created = materialize_discovered_roots(
            &mut candidate,
            &roots,
            existing_base,
            &session,
            client.normalized_url(),
        )?;
        if let Err(error) = runtime.store.save(&candidate) {
            rollback_created_markers(&created);
            return Err(error);
        }
        operation.finish_state(candidate);
        Ok(())
    }
    .await;
    refreshed
}

#[tauri::command]
pub(super) async fn start_pair(
    app: AppHandle,
    runtime: State<'_, Runtime>,
    workspace_id: String,
    remote_root_id: Option<String>,
    sync_root_id: String,
    local_root: String,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(present_error)?;
    let pairing_generation = runtime
        .auth_offboarding
        .admit_login()
        .map_err(present_error)?;
    let _publication = runtime.auth_publication.lock().await;
    let mut operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .map_err(present_error)?;
    let current = runtime.coordinator.snapshot();
    let was_first_pair = current.pair_count() == 0;

    // This is emitted only by the native folder dialog. Requiring an existing
    // empty, link-free folder prevents a guessed or existing sync tree from
    // being repurposed as a new base.
    let base = PathBuf::from(local_root.trim());
    if current
        .sync_root_base
        .as_ref()
        .is_some_and(|configured| configured != &base)
    {
        return Err(
            "All Drive locations use the existing local Drive folder; disconnect before choosing another."
                .to_string(),
        );
    }
    if current.sync_root_base.is_none() {
        ensure_empty_local_root(&base).map_err(present_error)?;
    }
    let base_guard = UnixRootGuard::acquire(&base, None).map_err(present_error)?;
    let session = runtime.current_session().map_err(present_error)?;
    let token = runtime.current_token(&session).map_err(present_error)?;
    let client = DriveHttpClient::new(&session.server_url).map_err(present_error)?;
    let selected = admit_user_session_response_during_publication(
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
    .map_err(present_error)?;
    let selected_manifest = admit_user_session_response_during_publication(
        &runtime,
        &session,
        &token,
        client.sync_root_manifest(&token, &selected).await,
    )
    .map_err(present_error)?;
    let selected = selected_manifest.root;
    let roots = vec![selected.clone()];

    if !runtime.auth_offboarding.may_publish(pairing_generation) {
        return Err("Pairing was canceled by a newer sign-in or Disconnect.".to_string());
    }
    runtime
        .require_captured_setup_session_during_publication(&session, &token)
        .map_err(present_error)?;

    let mut candidate = current;
    if candidate.sync_root_base.is_none() {
        candidate.sync_root_base = Some(base.clone());
    }
    let created = materialize_discovered_roots_with_guard(
        &mut candidate,
        &roots,
        &base_guard,
        &session,
        client.normalized_url(),
        true,
    )
    .map_err(present_error)?;
    let selected_pair_id = candidate
        .pairs()
        .find(|pair| {
            pair.workspace_id == selected.workspace_id
                && pair.remote_root_id == selected.root_file_id
        })
        .map(sync_pair_id)
        .ok_or_else(|| {
            present_error(DesktopError::InvalidState(
                "selected root was not materialized".to_string(),
            ))
        })?;
    candidate
        .activate_pair(&selected_pair_id)
        .map_err(present_error)?;
    if was_first_pair {
        candidate.launch_at_login = false;
    }
    if let Err(error) = runtime.store.save(&candidate) {
        rollback_created_markers(&created);
        return Err(present_error(error));
    }
    operation
        .publish_persisted_state(candidate.clone())
        .map_err(present_error)?;
    invalidate_pending_confirmation(&runtime);
    if !was_first_pair {
        operation.finish_state(candidate);
        drop(_publication);
        update_tray(&app, &runtime);
        return sync::sync_or_recheck(&app, &runtime, false).await;
    }
    if !enable_launch_at_login_after_pair(&runtime, &mut candidate) {
        operation.finish_state(candidate);
        update_tray(&app, &runtime);
        return Ok(runtime.view());
    }
    operation.finish_state(candidate);
    drop(_publication);
    update_tray(&app, &runtime);
    sync::start_polling(&app, &runtime);
    sync::sync_or_recheck(&app, &runtime, false).await
}

#[tauri::command]
pub(super) async fn select_pair(
    app: AppHandle,
    runtime: State<'_, Runtime>,
    pair_id: String,
) -> Result<DesktopView, String> {
    select_pair_impl(&app, &runtime, pair_id).await
}

pub(crate) async fn select_pair_impl(
    app: &AppHandle,
    runtime: &Runtime,
    pair_id: String,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(present_error)?;
    let _publication = runtime.auth_publication.lock().await;
    let mut operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .map_err(present_error)?;
    let mut candidate = runtime.coordinator.snapshot();
    let selected = candidate
        .pairs()
        .find(|pair| sync_pair_id(pair) == pair_id.trim())
        .cloned()
        .ok_or_else(|| "That Drive location is no longer configured.".to_string())?;
    let guard = UnixRootGuard::acquire(&selected.local_root, selected.local_root_identity.as_ref())
        .map_err(present_error)?;
    guard
        .require_exact_pair_marker(&PairMarker::from(&selected))
        .map_err(present_error)?;
    if candidate
        .activate_pair(pair_id.trim())
        .map_err(present_error)?
    {
        runtime.store.save(&candidate).map_err(present_error)?;
    }
    *runtime.session.lock().expect("session lock") = Some(SessionIdentity::new(
        &selected.server_url,
        &selected.account_email,
    ));
    operation.finish_state(candidate);
    invalidate_pending_confirmation(runtime);
    update_tray(app, runtime);
    sync::start_polling(app, runtime);
    Ok(runtime.view())
}

fn materialize_discovered_roots(
    state: &mut DesktopState,
    discovered: &[SyncRoot],
    requested_base: Option<PathBuf>,
    session: &SessionIdentity,
    normalized_server_url: &str,
) -> CoreResult<Vec<SyncPair>> {
    let roots = converge_sync_roots(discovered)?;
    let base = match (state.sync_root_base.as_ref(), requested_base) {
        (Some(current), Some(requested)) if current != &requested => {
            return Err(DesktopError::InvalidState(
                "all authorized Drive locations use the existing local Drive folder; disconnect before choosing another"
                    .to_string(),
            ))
        }
        (Some(current), _) => current.clone(),
        (None, Some(requested)) if state.pair_count() == 0 => {
            ensure_empty_local_root(&requested)?;
            state.sync_root_base = Some(requested.clone());
            requested
        }
        (None, _) => return Ok(Vec::new()),
    };
    let guard = UnixRootGuard::acquire(&base, None)?;
    materialize_discovered_roots_with_guard(
        state,
        &roots,
        &guard,
        session,
        normalized_server_url,
        false,
    )
}

fn materialize_discovered_roots_with_guard(
    state: &mut DesktopState,
    discovered: &[SyncRoot],
    base_guard: &UnixRootGuard,
    session: &SessionIdentity,
    normalized_server_url: &str,
    selected_only: bool,
) -> CoreResult<Vec<SyncPair>> {
    let roots = converge_sync_roots(discovered)?;
    let mut working = state.clone();
    let previously_active = working.pair.as_ref().map(sync_pair_id);
    if selected_only {
        working.record_selected_sync_root(&roots[0])?;
    } else {
        working.reconcile_sync_roots(&roots, Utc::now())?;
    }
    let base = working
        .sync_root_base
        .clone()
        .ok_or_else(|| DesktopError::InvalidState("Drive location base is missing".to_string()))?;
    let locations = if selected_only {
        vec![plan_selected_root_location(&working, &roots[0], &base)?]
    } else {
        plan_local_root_locations(&roots)?
    };
    let mut created = Vec::new();
    for location in locations {
        let root = roots
            .iter()
            .find(|root| root.id == location.root_id)
            .expect("location plan returned its root")
            .clone();
        if working.pairs().any(|pair| {
            pair.workspace_id == root.workspace_id && pair.remote_root_id == root.root_file_id
        }) {
            continue;
        }
        let local_root = base.join(&location.relative_path);
        let root_guard = match base_guard.ensure_child_root(&location.relative_path) {
            Ok(guard) => guard,
            Err(error) => {
                rollback_created_markers(&created);
                return Err(error);
            }
        };
        let pair = SyncPair {
            server_url: normalized_server_url.to_string(),
            account_email: session.email.clone(),
            workspace_id: root.workspace_id.clone(),
            workspace_name: root.label.clone(),
            remote_root_id: root.root_file_id.clone(),
            remote_root_name: root.root_file_id.as_ref().map(|_| root.label.clone()),
            local_root,
            local_root_identity: Some(root_guard.identity().clone()),
        };
        let mut next = working.clone();
        if let Err(error) = next
            .configure_pair(pair.clone())
            .and_then(|()| next.record_sync_root(&pair, root.clone()))
        {
            rollback_created_markers(&created);
            return Err(error);
        }
        match base_guard.write_or_recognize_child_pair_marker(
            &location.relative_path,
            &root_guard,
            &PairMarker::from(&pair),
        ) {
            Ok(PairMarkerDisposition::Created) => created.push(pair.clone()),
            Ok(PairMarkerDisposition::ExistingIdentical) => {}
            Err(error) => {
                rollback_created_markers(&created);
                return Err(error);
            }
        }
        working = next;
    }
    if let Some(previously_active) = previously_active {
        working.activate_pair(&previously_active)?;
    }
    *state = working;
    Ok(created)
}

fn rollback_created_markers(created: &[SyncPair]) {
    for pair in created.iter().rev() {
        if let Ok(guard) =
            UnixRootGuard::acquire(&pair.local_root, pair.local_root_identity.as_ref())
        {
            let _ = guard.remove_exact_pair_marker(&PairMarker::from(pair));
        }
    }
}

fn present_error(error: DesktopError) -> String {
    error.to_string()
}

/// Enable the paired desktop's startup entry only when its enabled state can
/// be persisted. A repair condition must stop any retained poller before the
/// lifecycle reservation is released, so a successful poll cannot hide it.
fn enable_launch_at_login_after_pair(runtime: &Runtime, candidate: &mut DesktopState) -> bool {
    if let Err(error) = runtime.platform.set_launch_at_login(true) {
        candidate.last_error = Some(format!(
            "Drive locations were paired, but Linux launch-at-sign-in could not be enabled: {error}"
        ));
        let _ = runtime.store.save(candidate);
        sync::stop_polling(runtime);
        return false;
    }
    candidate.launch_at_login = true;
    if let Err(error) = runtime.store.save(candidate) {
        let rollback = runtime.platform.set_launch_at_login(false);
        candidate.launch_at_login = false;
        candidate.last_error = Some(match rollback {
            Ok(()) => format!(
                "Drive locations were paired, but the Linux launch-at-sign-in preference could not be saved: {error}"
            ),
            Err(rollback_error) => format!(
                "Drive locations were paired, but Linux launch-at-sign-in needs repair after persistence and rollback failures: {error}; {rollback_error}"
            ),
        });
        let _ = runtime.store.save(candidate);
        sync::stop_polling(runtime);
        return false;
    }
    true
}

#[cfg(test)]
#[path = "roots/tests.rs"]
mod tests;

//! Fresh-folder replacement without changing the live binding before commit.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use shellx_drive_desktop_core::{SyncRootKind, SyncRootRole};

use super::*;

const STOP_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn replace_folder_impl(
    app: &AppHandle,
    runtime: &Arc<Runtime>,
    manager: &ConnectionManager,
    local_root: String,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(present_error)?;
    let base = PathBuf::from(local_root.trim());
    let id = manager
        .id_for_runtime(runtime)
        .ok_or_else(|| "Drive connection is no longer registered.".to_string())?;
    manager
        .validate_local_folder(&id, &base)
        .map_err(present_error)?;
    ensure_empty_local_root(&base).map_err(present_error)?;
    let before = runtime.coordinator.snapshot();
    if before.has_any_reviews() {
        return Err(
            "Resolve this server's pending reviews before replacing its folder.".to_string(),
        );
    }
    if before.pair.is_none() {
        return Err("Choose Drive content before replacing its folder.".to_string());
    }

    let was_polling = runtime
        .polling_enabled
        .load(std::sync::atomic::Ordering::Acquire);
    sync::stop_polling(runtime);
    let replaced = replace_stopped(runtime, manager, &id, base).await;
    // Both successful replacement and ordinary failure keep this connection
    // scheduled. A queued older generation cannot resume against a new tree.
    if was_polling
        && !runtime
            .coordinator
            .snapshot()
            .has_pending_disconnect_cleanup()
    {
        sync::start_polling(app, runtime);
    }
    update_tray(app, runtime);
    replaced
}

async fn replace_stopped(
    runtime: &Arc<Runtime>,
    manager: &ConnectionManager,
    id: &str,
    base: PathBuf,
) -> Result<DesktopView, String> {
    let mut stopped = tokio::time::timeout(
        STOP_TIMEOUT,
        crate::application::request_disconnect_after_sync(runtime),
    )
    .await
    .map_err(|_| "Drive is still stopping its active sync. Retry the folder change.".to_string())?
    .map_err(present_error)?;
    let _publication = runtime.auth_publication.lock().await;
    let mut operation = stopped.try_begin().map_err(present_error)?.ok_or_else(|| {
        "Drive sync restarted before its folder could be replaced. Retry the change.".to_string()
    })?;
    let current = runtime.coordinator.snapshot();
    if current.has_any_reviews() {
        return Err(
            "Resolve this server's pending reviews before replacing its folder.".to_string(),
        );
    }
    runtime
        .require_candidate_recovery_complete()
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(present_error)?;
    let session = runtime.current_session().map_err(present_error)?;
    let token = runtime.current_token(&session).map_err(present_error)?;
    let client = DriveHttpClient::new(&session.server_url).map_err(present_error)?;
    let configured = current
        .pairs()
        .map(|pair| {
            if let Some(metadata) = current.sync_root_for_pair(pair) {
                return Ok(metadata.root.clone());
            }
            if pair.remote_root_id.is_none() {
                return Ok(SyncRoot {
                    id: format!("workspace:{}", pair.workspace_id),
                    kind: SyncRootKind::Workspace,
                    workspace_id: pair.workspace_id.clone(),
                    root_file_id: None,
                    grant_id: None,
                    owner_label: "Existing workspace".to_string(),
                    role: SyncRootRole::Viewer,
                    access_generation: 1,
                    expires_at: None,
                    label: pair.workspace_name.clone(),
                });
            }
            Err(DesktopError::InvalidState(
            "an existing shared folder has no saved root identity; it cannot be safely replaced"
                .to_string(),
        ))
        })
        .collect::<CoreResult<Vec<_>>>()
        .map_err(present_error)?;
    let roots = admit_user_session_response_during_publication(
        runtime,
        &session,
        &token,
        client
            .revalidate_configured_sync_roots(&token, &configured)
            .await,
    )
    .map_err(present_error)?;
    if roots.len() != configured.len() {
        return Err(
            "Drive access changed. Review this server before replacing its folder.".to_string(),
        );
    }
    for root in &roots {
        admit_user_session_response_during_publication(
            runtime,
            &session,
            &token,
            client.sync_root_manifest(&token, root).await,
        )
        .map_err(present_error)?;
    }
    runtime
        .require_captured_setup_session_during_publication(&session, &token)
        .map_err(present_error)?;

    let _admission = manager.admission.lock().await;
    manager
        .validate_local_folder(id, &base)
        .map_err(present_error)?;
    ensure_empty_local_root(&base).map_err(present_error)?;
    let guard = UnixRootGuard::acquire(&base, None).map_err(present_error)?;
    guard.ensure_empty_root().map_err(present_error)?;
    let selected = current.pair.as_ref().map(remote_subject);
    let history = pair_history(&current);
    let mut candidate = fresh_folder_state(&current, base);
    let created = materialize_discovered_roots_with_guard(
        &mut candidate,
        &roots,
        &guard,
        &session,
        client.normalized_url(),
        false,
    )
    .map_err(present_error)?;
    let restored = restore_pair_history(&mut candidate, &history, selected);
    if let Err(error) = restored.and_then(|()| runtime.store.save(&candidate)) {
        rollback_created_markers(&created);
        return Err(present_error(error));
    }
    // The lifecycle reservation keeps the in-memory old binding intact until
    // the complete candidate has reached the protected state store.
    operation
        .publish_persisted_state(candidate.clone())
        .map_err(present_error)?;
    operation.finish_state(candidate);
    invalidate_pending_confirmation(runtime);
    runtime.local_usage_cache.invalidate();
    Ok(runtime.view())
}

type RemoteSubject = (String, Option<String>);
type PairHistory = BTreeMap<RemoteSubject, (Vec<shellx_drive_desktop_core::ActivityEntry>, bool)>;

fn remote_subject(pair: &SyncPair) -> RemoteSubject {
    (pair.workspace_id.clone(), pair.remote_root_id.clone())
}

fn pair_history(state: &DesktopState) -> PairHistory {
    state
        .pair
        .iter()
        .map(|pair| (remote_subject(pair), (state.activity.clone(), state.paused)))
        .chain(state.inactive_pairs.iter().map(|profile| {
            (
                remote_subject(&profile.pair),
                (profile.activity.clone(), profile.paused),
            )
        }))
        .collect()
}

fn fresh_folder_state(state: &DesktopState, base: PathBuf) -> DesktopState {
    let mut candidate = state.clone();
    candidate.pair = None;
    candidate.inactive_pairs.clear();
    candidate.sync_roots.clear();
    candidate.sync_root_base = Some(base);
    candidate.sync_cycle_resume_pair_id = None;
    candidate.baseline.clear();
    candidate.change_cursor = 0;
    candidate.reviews.clear();
    candidate.activity.clear();
    candidate.last_successful_sync = None;
    candidate.last_error = None;
    candidate
}

fn restore_pair_history(
    state: &mut DesktopState,
    history: &PairHistory,
    selected: Option<RemoteSubject>,
) -> CoreResult<()> {
    let selected_id = state
        .pairs()
        .find(|pair| selected.as_ref() == Some(&remote_subject(pair)))
        .map(sync_pair_id);
    if let Some(pair) = state.pair.as_ref() {
        if let Some((activity, paused)) = history.get(&remote_subject(pair)) {
            state.activity = activity.clone();
            state.paused = *paused;
        }
    }
    for profile in &mut state.inactive_pairs {
        if let Some((activity, paused)) = history.get(&remote_subject(&profile.pair)) {
            profile.activity = activity.clone();
            profile.paused = *paused;
        }
    }
    if let Some(selected_id) = selected_id {
        state.activate_pair(&selected_id)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "replacement/tests.rs"]
mod tests;

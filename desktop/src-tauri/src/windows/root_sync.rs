//! Role-aware desktop root discovery and deterministic local materialization.
//!
//! The server remains the sole authority for root IDs and roles. This module
//! retains those opaque subjects in non-secret state, while individual pair
//! folders remain independently marker-bound for the existing sync engine.

use super::*;
use crate::application::sync_terminal::session::admit_user_session_response_during_publication;
use tauri::AppHandle;

/// Refresh configured authority before any manual, periodic, or startup sync.
/// Adding a newly available root requires an explicit picker choice.
pub(crate) async fn refresh_authorized_roots(runtime: &Runtime) -> CoreResult<()> {
    // Discovery can create a configured root, local directory, and pair
    // marker. A pending Disconnect journal owns a frozen cleanup scope, so
    // reject before reserving or observing any new authority.
    runtime.ensure_disconnect_cleanup_complete()?;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let current = runtime.coordinator.snapshot();
    let refresh = async {
        let session = runtime.current_session()?;
        let token = runtime.current_token(&session)?;
        let client = DriveHttpClient::new(&session.server_url)?;
        let (roots, overflow) = crate::application::root_discovery::discover_for_sync_refresh(
            runtime, &session, &token, &client, &current,
        )
        .await?;
        let mut candidate = current.clone();
        candidate.root_discovery_overflow = overflow;
        let requested_base = candidate.sync_root_base.clone();
        let materialized = materialize_discovered_roots(
            &mut candidate,
            &roots,
            requested_base,
            &session,
            client.normalized_url(),
            false,
        )?;
        if let Err(error) = runtime.store.save(&candidate) {
            rollback_created_markers(&materialized.created_markers);
            return Err(error);
        }
        operation.finish_state(candidate);
        drop(materialized);
        Ok(())
    }
    .await;
    if refresh.is_err() {
        // Drop releases the lifecycle reservation without publishing its
        // in-memory candidate. Existing local bytes and markers remain exact.
    }
    refresh
}

#[tauri::command]
pub(super) async fn start_pair(
    app: tauri::AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    workspace_id: String,
    remote_root_id: Option<String>,
    sync_root_id: String,
    local_root: String,
) -> Result<DesktopView, String> {
    manager.ensure_mutation_allowed().map_err(user_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(user_error)?;
    start_pair_impl(
        &app,
        &runtime,
        &manager,
        workspace_id,
        remote_root_id,
        sync_root_id,
        local_root,
    )
    .await
}

pub(crate) async fn start_pair_impl(
    app: &tauri::AppHandle,
    runtime: &Arc<Runtime>,
    manager: &ConnectionManager,
    workspace_id: String,
    remote_root_id: Option<String>,
    sync_root_id: String,
    local_root: String,
) -> Result<DesktopView, String> {
    manager.ensure_mutation_allowed().map_err(user_error)?;
    runtime
        .require_candidate_recovery_complete()
        .map_err(user_error)?;
    // Pairing discovers authority and may create a local directory and pair
    // marker. Honor the durable Disconnect cleanup journal before reserving a
    // lifecycle operation or contacting the server.
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(user_error)?;
    let pairing_generation = runtime.auth_offboarding.admit_login().map_err(user_error)?;
    let _auth_publication = runtime.auth_publication.lock().await;
    let mut operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .map_err(user_error)?;
    let current = runtime.coordinator.snapshot();
    let base = PathBuf::from(local_root.trim());
    if !base.exists() {
        return Err("Choose an existing empty folder for the local Drive tree.".to_string());
    }
    let session = runtime.current_session().map_err(user_error)?;
    let token = runtime.current_token(&session).map_err(user_error)?;
    let client = DriveHttpClient::new(&session.server_url).map_err(user_error)?;
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
    .map_err(user_error)?;
    // Pairing validates the exact opaque subject up front. An item grant can
    // never fall back to its workspace manifest or reveal a sibling locally.
    let selected_manifest = admit_user_session_response_during_publication(
        &runtime,
        &session,
        &token,
        client.sync_root_manifest(&token, &selected).await,
    )
    .map_err(user_error)?;
    // The scoped manifest is the last authority observation before a local
    // root becomes active. Preserve a narrowed role/generation instead of
    // materializing the possibly older discovery snapshot.
    let selected = selected_manifest.root;
    let roots = vec![selected.clone()];

    if !runtime.auth_offboarding.may_publish(pairing_generation) {
        return Err("Pairing was canceled by a newer sign-in or Disconnect.".to_string());
    }
    runtime
        .require_captured_setup_session_during_publication(&session, &token)
        .map_err(user_error)?;

    let id = manager
        .id_for_runtime(runtime)
        .ok_or_else(|| "That server connection is no longer available.".to_string())?;
    let admission = manager.admission.lock().await;
    if current.pair_count() == 0 {
        manager
            .validate_local_folder(&id, &base)
            .map_err(user_error)?;
    } else {
        manager
            .validate_add_root_folder(&id, &base)
            .map_err(user_error)?;
    }
    let mut candidate = current;
    let materialized = materialize_discovered_roots(
        &mut candidate,
        &roots,
        Some(base),
        &session,
        client.normalized_url(),
        true,
    )
    .map_err(user_error)?;
    let selected_pair_id = candidate
        .pairs()
        .find(|pair| {
            pair.workspace_id == selected.workspace_id
                && pair.remote_root_id == selected.root_file_id
        })
        .map(sync_pair_id)
        .ok_or_else(|| {
            user_error(DesktopError::InvalidState(
                "selected root was not materialized".to_string(),
            ))
        })?;
    candidate
        .activate_pair(&selected_pair_id)
        .map_err(user_error)?;
    if let Err(error) = runtime.store.save(&candidate) {
        rollback_created_markers(&materialized.created_markers);
        return Err(user_error(error));
    }
    operation
        .publish_persisted_state(candidate.clone())
        .map_err(user_error)?;
    drop(materialized);
    invalidate_pending_confirmation(&runtime);
    operation.finish_state(candidate);
    drop(admission);
    drop(_auth_publication);
    update_tray(&app, &runtime);
    start_polling(&app, &runtime);
    if manager.may_sync(runtime) {
        sync_now_impl(&app, &runtime).await
    } else {
        Ok(runtime.view())
    }
}

#[tauri::command]
pub(super) async fn add_root(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    workspace_id: String,
    remote_root_id: Option<String>,
    sync_root_id: String,
) -> Result<DesktopView, String> {
    manager.ensure_mutation_allowed().map_err(user_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(user_error)?;
    let base = runtime
        .coordinator
        .snapshot()
        .sync_root_base
        .ok_or_else(|| "Connect a first Drive root before adding another.".to_string())?;
    start_pair_impl(
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

pub(crate) async fn replace_folder_impl(
    app: &AppHandle,
    runtime: &Arc<Runtime>,
    manager: &ConnectionManager,
    local_root: String,
) -> Result<DesktopView, String> {
    manager.ensure_mutation_allowed().map_err(user_error)?;
    runtime
        .require_candidate_recovery_complete()
        .map_err(user_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(user_error)?;
    if runtime.coordinator.snapshot().has_any_reviews() {
        return Err(
            "Resolve this server's pending reviews before changing its local folder.".to_string(),
        );
    }
    let was_polling = runtime.polling_enabled.load(Ordering::Acquire);
    stop_polling(runtime);
    let result = replace_folder_transaction(app, runtime, manager, local_root).await;
    if was_polling || result.is_ok() {
        start_polling(app, runtime);
    }
    result
}

async fn replace_folder_transaction(
    app: &AppHandle,
    runtime: &Arc<Runtime>,
    manager: &ConnectionManager,
    local_root: String,
) -> Result<DesktopView, String> {
    let mut stop_request = tokio::time::timeout(
        Duration::from_secs(30),
        crate::application::request_disconnect_after_sync(runtime),
    )
    .await
    .map_err(|_| {
        "This server's sync is still stopping. Retry the folder change when it has stopped."
            .to_string()
    })?
    .map_err(user_error)?;
    let generation = runtime.auth_offboarding.admit_login().map_err(user_error)?;
    let _publication = runtime.auth_publication.lock().await;
    let mut operation = stop_request
        .try_begin()
        .map_err(user_error)?
        .ok_or_else(|| "This server started syncing again. Retry the folder change.".to_string())?;
    let current = runtime.coordinator.snapshot();
    if current.has_any_reviews() {
        return Err(
            "Resolve this server's pending reviews before changing its local folder.".to_string(),
        );
    }
    let selected_pair = current.pair.clone().ok_or_else(|| {
        "Connect this server to Drive content before changing its folder.".to_string()
    })?;
    let session = runtime.current_session().map_err(user_error)?;
    let bearer = runtime.current_token(&session).map_err(user_error)?;
    let client = DriveHttpClient::new(&session.server_url).map_err(user_error)?;
    let (discovered, _) = crate::application::root_discovery::discover_for_sync_refresh(
        runtime, &session, &bearer, &client, &current,
    )
    .await
    .map_err(user_error)?;
    let mut roots = Vec::new();
    let mut histories = HashMap::new();
    for pair in current.pairs() {
        let root = discovered
            .iter()
            .find(|root| {
                root.workspace_id == pair.workspace_id && root.root_file_id == pair.remote_root_id
            })
            .or_else(|| {
                current
                    .sync_root_for_pair(pair)
                    .map(|metadata| &metadata.root)
            })
            .ok_or_else(|| {
                "Recheck this server's Drive content before changing its folder.".to_string()
            })?;
        let selected = admit_user_session_response_during_publication(
            runtime,
            &session,
            &bearer,
            client
                .revalidate_selected_sync_root(
                    &bearer,
                    &root.id,
                    &pair.workspace_id,
                    pair.remote_root_id.as_deref(),
                )
                .await,
        )
        .map_err(user_error)?;
        let manifest = admit_user_session_response_during_publication(
            runtime,
            &session,
            &bearer,
            client.sync_root_manifest(&bearer, &selected).await,
        )
        .map_err(user_error)?;
        let activity = if pair == &selected_pair {
            current.activity.clone()
        } else {
            current
                .inactive_pairs
                .iter()
                .find(|profile| profile.pair == *pair)
                .map(|profile| profile.activity.clone())
                .unwrap_or_default()
        };
        histories.insert(
            (pair.workspace_id.clone(), pair.remote_root_id.clone()),
            activity,
        );
        roots.push(manifest.root);
    }
    if !runtime.auth_offboarding.may_publish(generation) {
        return Err("The folder change was canceled by a newer sign-in or removal.".to_string());
    }
    runtime
        .require_captured_setup_session_during_publication(&session, &bearer)
        .map_err(user_error)?;
    let base = PathBuf::from(local_root.trim());
    ensure_empty_local_root(&base).map_err(user_error)?;
    let id = manager
        .id_for_runtime(runtime)
        .ok_or_else(|| "That server connection is no longer available.".to_string())?;
    let _admission = manager.admission.lock().await;
    manager
        .validate_local_folder(&id, &base)
        .map_err(user_error)?;
    let _old_roots =
        guard_configured_pair_roots(&current, &selected_pair.local_root).map_err(user_error)?;
    let mut candidate = current.clone();
    candidate.pair = None;
    candidate.inactive_pairs.clear();
    candidate.sync_roots.clear();
    candidate.sync_root_base = None;
    candidate.sync_cycle_resume_pair_id = None;
    candidate.baseline.clear();
    candidate.change_cursor = 0;
    candidate.reviews.clear();
    candidate.activity.clear();
    candidate.last_successful_sync = None;
    candidate.last_error = None;
    let materialized = materialize_discovered_roots(
        &mut candidate,
        &roots,
        Some(base),
        &session,
        client.normalized_url(),
        false,
    )
    .map_err(user_error)?;
    let selected_id = candidate
        .pairs()
        .find(|pair| {
            pair.workspace_id == selected_pair.workspace_id
                && pair.remote_root_id == selected_pair.remote_root_id
        })
        .map(sync_pair_id)
        .ok_or_else(|| {
            "The saved Drive content could not be configured in the new folder.".to_string()
        });
    let selected_id = match selected_id {
        Ok(id) => id,
        Err(error) => {
            rollback_created_markers(&materialized.created_markers);
            return Err(error);
        }
    };
    if let Err(error) = candidate.activate_pair(&selected_id) {
        rollback_created_markers(&materialized.created_markers);
        return Err(user_error(error));
    }
    if let Some(pair) = candidate.pair.as_ref() {
        candidate.activity = histories
            .remove(&(pair.workspace_id.clone(), pair.remote_root_id.clone()))
            .unwrap_or_default();
    }
    for profile in &mut candidate.inactive_pairs {
        profile.activity = histories
            .remove(&(
                profile.pair.workspace_id.clone(),
                profile.pair.remote_root_id.clone(),
            ))
            .unwrap_or_default();
    }
    if let Err(error) = runtime.store.save(&candidate) {
        rollback_created_markers(&materialized.created_markers);
        return Err(user_error(error));
    }
    operation.finish_state(candidate);
    runtime.local_usage_cache.invalidate();
    invalidate_pending_confirmation(runtime);
    update_tray(app, runtime);
    Ok(runtime.view())
}

/// Mutate a detached candidate state only. Callers save it atomically before
/// publishing it to the coordinator. Newly written markers are returned for
/// exact rollback if that save fails; existing orphan-identical markers are
/// intentionally left for the corresponding retry.
struct MaterializedRoots {
    created_markers: Vec<SyncPair>,
    _directory_pins: Vec<Vec<fs::File>>,
    _root_guards: Vec<pair_root_identity::PairRootGuard>,
}

fn materialize_discovered_roots(
    state: &mut DesktopState,
    discovered: &[SyncRoot],
    requested_base: Option<PathBuf>,
    session: &SessionIdentity,
    normalized_server_url: &str,
    selected_only: bool,
) -> CoreResult<MaterializedRoots> {
    let roots = converge_sync_roots(discovered)?;
    let mut working = state.clone();
    let base = choose_root_base(&mut working, requested_base)?;
    adopt_legacy_pairs(&mut working, &roots)?;
    if selected_only {
        working.record_selected_sync_root(&roots[0])?;
    } else {
        working.reconcile_sync_roots(&roots, Utc::now())?;
    }
    let locations = if selected_only {
        vec![shellx_drive_desktop_core::plan_selected_root_location(
            &working,
            &roots[0],
            base.as_deref().ok_or_else(|| DesktopError::NeedsSetup)?,
        )?]
    } else {
        plan_local_root_locations(&roots)?
    };
    let mut materialized = MaterializedRoots {
        created_markers: Vec::new(),
        _directory_pins: Vec::new(),
        _root_guards: Vec::new(),
    };
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
        let Some(base) = base.as_deref() else {
            // A pre-role-aware retained pair has no authoritative local
            // container. Discovery can still mark/remediate old roots, but
            // cannot invent a path for a new server authority.
            continue;
        };
        let directory_pins = match ensure_local_directory_pinned(base, &location.relative_path) {
            Ok(pins) => pins,
            Err(error) => {
                rollback_created_markers(&materialized.created_markers);
                return Err(error);
            }
        };
        let local_root = base.join(&location.relative_path);
        let root_guard = match guard_configured_pair_roots(&working, &local_root) {
            Ok(guard) => guard,
            Err(error) => {
                rollback_created_markers(&materialized.created_markers);
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
            local_root: local_root.clone(),
            local_root_identity: Some(root_guard.required_identity.clone()),
        };
        let mut next = working.clone();
        if let Err(error) = next
            .configure_pair(pair.clone())
            .and_then(|()| next.record_sync_root(&pair, root.clone()))
        {
            rollback_created_markers(&materialized.created_markers);
            return Err(error);
        }
        match root_guard.write_or_recognize_marker(&local_root, &PairMarker::from(&pair)) {
            Ok(PairMarkerDisposition::Created) => materialized.created_markers.push(pair.clone()),
            Ok(PairMarkerDisposition::ExistingIdentical) => {}
            Err(error) => {
                rollback_created_markers(&materialized.created_markers);
                return Err(error);
            }
        }
        materialized._directory_pins.push(directory_pins);
        materialized._root_guards.push(root_guard);
        working = next;
    }
    *state = working;
    Ok(materialized)
}

fn choose_root_base(
    state: &mut DesktopState,
    requested_base: Option<PathBuf>,
) -> CoreResult<Option<PathBuf>> {
    match (&state.sync_root_base, requested_base) {
        (Some(current), Some(requested)) if current != &requested => Err(DesktopError::InvalidState(
            "all authorized Drive roots use the existing local Drive folder; choose that folder or disconnect before selecting another"
                .to_string(),
        )),
        (Some(current), _) => Ok(Some(current.clone())),
        (None, Some(requested)) => {
            if state.pair_count() != 0 {
                return Err(DesktopError::InvalidState(
                    "a retained legacy Drive location has no role-aware local root container; re-pair it before adding shared roots"
                        .to_string(),
                ));
            }
            ensure_empty_local_root(&requested)?;
            state.sync_root_base = Some(requested.clone());
            Ok(Some(requested))
        }
        (None, None) => Ok(None),
    }
}

fn adopt_legacy_pairs(state: &mut DesktopState, roots: &[SyncRoot]) -> CoreResult<()> {
    let pairs = state.pairs().cloned().collect::<Vec<_>>();
    for pair in pairs {
        if state.sync_root_for_pair(&pair).is_some() {
            continue;
        }
        if let Some(root) = roots.iter().find(|root| {
            root.workspace_id == pair.workspace_id && root.root_file_id == pair.remote_root_id
        }) {
            state.record_sync_root(&pair, root.clone())?;
        }
    }
    Ok(())
}

fn rollback_created_markers(created: &[SyncPair]) {
    for pair in created.iter().rev() {
        let _ = pair_marker::remove(&pair.local_root, &PairMarker::from(pair));
    }
}

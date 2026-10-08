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
    runtime: State<'_, Runtime>,
    workspace_id: String,
    remote_root_id: Option<String>,
    sync_root_id: String,
    local_root: String,
) -> Result<DesktopView, String> {
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
    let was_first_pair = current.pair_count() == 0;
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
    // New materialization intentionally starts disabled until all marker and
    // state writes succeeded. This is the same durable publication ordering
    // used by the former one-root pairing path.
    if was_first_pair {
        candidate.launch_at_login = false;
    }
    if let Err(error) = runtime.store.save(&candidate) {
        rollback_created_markers(&materialized.created_markers);
        return Err(user_error(error));
    }
    operation
        .publish_persisted_state(candidate.clone())
        .map_err(user_error)?;
    drop(materialized);
    invalidate_pending_confirmation(&runtime);
    if !was_first_pair {
        operation.finish_state(candidate);
        drop(_auth_publication);
        update_tray(&app, &runtime);
        return sync_now_impl(&app, &runtime).await;
    }
    if let Err(error) = runtime.platform.set_launch_at_login(true) {
        candidate.last_error = Some(format!(
            "Drive roots were paired, but Windows launch-at-sign-in could not be enabled: {error}"
        ));
        let _ = runtime.store.save(&candidate);
        operation.finish_state(candidate);
        update_tray(&app, &runtime);
        return Ok(runtime.view());
    }
    candidate.launch_at_login = true;
    if let Err(error) = runtime.store.save(&candidate) {
        let rollback = runtime.platform.set_launch_at_login(false);
        candidate.launch_at_login = false;
        candidate.last_error = Some(match rollback {
            Ok(()) => format!(
                "Drive roots were paired, but their launch-at-sign-in preference could not be saved: {error}"
            ),
            Err(rollback_error) => format!(
                "Drive roots were paired, but launch-at-sign-in needs repair after persistence and rollback failures: {error}; {rollback_error}"
            ),
        });
        let _ = runtime.store.save(&candidate);
        operation.finish_state(candidate);
        update_tray(&app, &runtime);
        return Ok(runtime.view());
    }
    operation.finish_state(candidate);
    drop(_auth_publication);
    update_tray(&app, &runtime);
    start_polling(&app, &runtime);
    sync_now_impl(&app, &runtime).await
}

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
    start_pair(
        app,
        runtime,
        workspace_id,
        remote_root_id,
        sync_root_id,
        base.to_string_lossy().into_owned(),
    )
    .await
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

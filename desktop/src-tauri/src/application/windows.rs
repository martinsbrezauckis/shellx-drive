//! Windows native command and execution implementation.

use super::lifecycle::persist_paused_state;
use super::*;
use crate::application::sync_terminal::session::admit_user_session_response;

#[path = "../windows/app_shell.rs"]
mod app_shell;
#[path = "../windows/app_updates.rs"]
mod app_updates;
#[path = "../windows/candidate_recovery_runtime.rs"]
mod candidate_recovery_runtime;
#[path = "../windows/candidate_startup_recovery.rs"]
mod candidate_startup_recovery;
#[path = "../windows/disconnect_cleanup.rs"]
pub(crate) mod disconnect_cleanup;
#[path = "../windows/disconnect_retirement.rs"]
mod disconnect_retirement;
#[path = "../windows/download_publication.rs"]
mod download_publication;
#[path = "../windows/handle_relative_file.rs"]
mod handle_relative_file;
#[path = "../windows/instance_lock.rs"]
mod instance_lock;
#[path = "../windows/pair_marker.rs"]
mod pair_marker;
#[path = "../windows/pair_root_identity.rs"]
mod pair_root_identity;
#[path = "../windows/pair_root_publication.rs"]
mod pair_root_publication;
#[path = "../windows/pair_selection.rs"]
pub(crate) mod pair_selection;
#[path = "../windows/pending_session_retirement.rs"]
mod pending_session_retirement;
#[path = "../windows/remote_entry.rs"]
mod remote_entry;
#[path = "../windows/remote_revocations.rs"]
mod remote_revocations;
#[path = "../windows/replacement_guard.rs"]
mod replacement_guard;
#[path = "../windows/review_execution.rs"]
mod review_execution;
#[path = "../windows/root_materialization.rs"]
mod root_materialization;
#[path = "../windows/root_sync.rs"]
pub(crate) mod root_sync;
#[path = "../windows/session_credentials.rs"]
mod session_credentials;
#[path = "../windows/startup.rs"]
pub(crate) mod startup;
#[path = "../windows/sync_runtime.rs"]
pub(crate) mod sync_runtime;
#[path = "../windows/transfer_execution.rs"]
mod transfer_execution;
#[path = "../windows/transfer_types.rs"]
mod transfer_types;
#[path = "../windows/tray_policy.rs"]
mod tray_policy;
#[path = "../windows/uninstall_offboarding.rs"]
mod uninstall_offboarding;
#[path = "../windows/verified_staging.rs"]
mod verified_staging;

pub(crate) use app_shell::update_tray;
use app_shell::{notify_actionable, user_error};
use candidate_startup_recovery::recover_staged_candidates_before_polling;
use download_publication::*;
use pair_root_identity::guard_configured_pair_roots;
use remote_entry::remote_entry;
use remote_revocations::retire_canceled_login;
use review_execution::{execute_review_decision, ReviewExecution};
use root_materialization::*;
use session_credentials::{disconnect_credentials, publish_authenticated_session};
use sync_runtime::{
    recheck_reviews_impl, recheck_reviews_with_budget, start_polling, stop_polling, sync_now_impl,
};
use transfer_execution::*;
use transfer_types::*;

use crate::session_identity::{
    disconnect_identity, stored_credential_needs_remote_retirement, ServiceCredentialKey,
    SessionIdentity,
};

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{Seek, Write},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Duration,
};

use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use shellx_drive_desktop_core::{
    apply_local_path_compatibility_reviews, candidate_recovery_locator,
    capture_local_operation_boundary, classify_exact_credential_readback,
    classify_exact_credential_removal, classify_exact_credential_write,
    compare_staged_candidate_recovery_order, confirm_direct_retirement,
    confirm_pending_remote_retirements, confirm_remote_retirement, converge_sync_roots,
    copy_and_hash_reader_bounded, created_remote_response_matches, default_state_path,
    download_precondition_matches, download_publication_disposition, download_staging_root,
    ensure_empty_local_root, ensure_local_operation_boundary, ensure_private_staging_directory,
    ensure_tree_has_no_links, folder_remote_witness_matches, hash_reader_bounded, hex_digest,
    initialize_owned_staging_root, inspect_local_tree_with_budget,
    inspect_local_tree_with_budget_and_cancellation, is_path_compatibility_review,
    map_remote_paths, pending_record_requires_authorized_retirement, plan_local_root_locations,
    remote_move_response_matches, resolve_review_decision, restore_staging_root,
    restored_remote_response_matches, review_confirmation_fingerprint,
    reviewed_local_subtree_matches_baseline, reviewed_remote_subtree_matches_baseline,
    scan_local_tree, select_pending_retirement_authorizer, staged_candidate_recovery_action,
    state_after_confirmed_remote_retirement, sync_pair_id, trashed_remote_response_matches,
    updated_remote_response_matches, upload_staging_root, verify_local_operation_boundary,
    ActivityEntry, BaselineEntry, CredentialStore, DesktopError, DesktopState,
    DisconnectCleanupIntent, DownloadPrecondition, DownloadPublicationDisposition, DriveHttpClient,
    ExactCredentialRead, ExactCredentialRemoval, ExactCredentialWrite, ExistingFileTransfer,
    FolderMovePrecondition, LocalEntry, LocalScanLimits, LoginOutcome, OwnedStagingRoot,
    PairMarker, PairMarkerDisposition, PendingWindowsCredentialStore, ReadBudget, ReconcilePlan,
    RemoteEntry, RemoteEntryKind, RemoteFileKind, RemoteMoveTransfer, RemoteSessionRecord,
    Result as CoreResult, ReviewAction, ReviewDecision, ReviewItem, ReviewKind,
    StagedCandidateRecoveryAction, StateStore, SyncAction, SyncCycleBudget, SyncPair,
    SyncPassLimits, SyncRoot, SyncRun, SyncStatus, WindowsCredentialStore,
    WindowsDirectoryIdentity, CANDIDATE_RECOVERY_PAUSED_ERROR,
};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State,
};

/// Verify the pinned physical root and exact marker immediately before a
/// remote mutation, and retain that pin until the request completes.
async fn with_current_pair_remote_mutation<T, F, Fut>(
    state: &DesktopState,
    pair: &SyncPair,
    mutate: F,
) -> CoreResult<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = CoreResult<T>>,
{
    let _guard = guard_configured_pair_roots(state, &pair.local_root)?;
    mutate().await
}
use tauri_plugin_notification::NotificationExt;
const POLL_INTERVAL: Duration = Duration::from_secs(20);
const OFFLINE_BACKOFF: Duration = Duration::from_secs(60);
const MAX_DESKTOP_SYNC_PASS_DURATION: Duration = Duration::from_secs(2 * 60 * 60);
const DESKTOP_SYNC_FREE_SPACE_RESERVE_BYTES: u64 = 512 * 1024 * 1024;
static NEXT_STAGING_BATCH: AtomicU64 = AtomicU64::new(0);

impl Runtime {
    fn new() -> CoreResult<Self> {
        let platform = Box::new(crate::platform::windows::WindowsPlatformServices::default());
        let (store, mut state) = Self::load_state()?;
        if disconnect_cleanup::resume_disconnected_local_cleanup(&store, &mut state).is_err() {
            // The durable journal remains intact. Launch in its Error
            // projection so the user can retry the same exact cleanup
            // through Disconnect instead of being locked out of the app.
            state.last_error =
                Some(disconnect_cleanup::DISCONNECT_CLEANUP_PENDING_ERROR.to_string());
            let _ = store.save(&state);
        }
        Ok(Self::from_loaded_state(platform, store, state))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginReply {
    kind: &'static str,
    account_email: String,
}

struct UploadSnapshot {
    area: OwnedStagingRoot,
    batch: PathBuf,
    payload_file: Mutex<Option<fs::File>>,
    local: LocalEntry,
}
#[tauri::command]
async fn login_password(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
    server_url: String,
    email: String,
    password: String,
) -> Result<LoginReply, String> {
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(user_error)?;
    let client = DriveHttpClient::new(&server_url).map_err(user_error)?;
    runtime
        .require_candidate_recovery_login_identity(client.normalized_url(), &email)
        .map_err(user_error)?;
    // A fresh password attempt invalidates any older in-memory 202
    // continuation before this request starts. Never leave a prior
    // password reachable after a replacement login attempt.
    let generation = runtime.auth_offboarding.admit_login().map_err(user_error)?;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    let outcome = async {
        runtime.ensure_login_matches_retained_pair(client.normalized_url(), &email)?;
        let outcome = client.login_password(&email, &password).await?;
        Ok::<_, DesktopError>((client, outcome))
    }
    .await;
    let (client, outcome) = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            if runtime.auth_offboarding.may_publish(generation) {
                *runtime.pending_login.lock().expect("pending login lock") = None;
            }
            return Err(user_error(error));
        }
    };
    let _publication = runtime.auth_publication.lock().await;
    if !runtime.auth_offboarding.may_publish(generation) {
        retire_canceled_login(&runtime, &client, &outcome)
            .await
            .map_err(user_error)?;
        return Err("Sign-in was canceled by a newer sign-in or disconnect.".to_string());
    }
    match outcome {
        LoginOutcome::Authenticated {
            bearer_token,
            account_email,
            session_id,
            expires_at,
            ..
        } => {
            *runtime.pending_login.lock().expect("pending login lock") = None;
            publish_authenticated_session(
                &runtime,
                &client,
                &bearer_token,
                &account_email,
                &session_id,
                expires_at,
                generation,
            )
            .await
            .map_err(user_error)?;
            update_tray(&app, &runtime);
            Ok(LoginReply {
                kind: "authenticated",
                account_email,
            })
        }
        LoginOutcome::RequiresSecondFactor { account_email } => {
            runtime
                .ensure_login_matches_retained_pair(client.normalized_url(), &account_email)
                .map_err(user_error)?;
            *runtime.pending_login.lock().expect("pending login lock") = Some(PendingLogin {
                server_url: client.normalized_url().to_string(),
                email: account_email.clone(),
                password,
                generation,
            });
            Ok(LoginReply {
                kind: "requires_second_factor",
                account_email,
            })
        }
    }
}

#[tauri::command]
async fn continue_login(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
    email: String,
    password: String,
    totp_code: Option<String>,
    recovery_code: Option<String>,
) -> Result<LoginReply, String> {
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(user_error)?;
    let pending_server_url = runtime
        .pending_login
        .lock()
        .expect("pending login lock")
        .as_ref()
        .map(|pending| pending.server_url.clone())
        .ok_or_else(|| {
            "Start with password sign-in before entering a second factor.".to_string()
        })?;
    let client = DriveHttpClient::new(&pending_server_url).map_err(user_error)?;
    runtime
        .require_candidate_recovery_login_identity(client.normalized_url(), &email)
        .map_err(user_error)?;
    let pending = runtime
        .pending_login
        .lock()
        .expect("pending login lock")
        .take()
        .ok_or_else(|| {
            "Start with password sign-in before entering a second factor.".to_string()
        })?;
    // The webview repeats the fields so a refresh can recover its form. The
    // in-memory values must still match the 202 continuation; never use a
    // secret received from persistent state.
    if pending.email != email || pending.password != password {
        return Err("Password sign-in changed; start sign-in again.".to_string());
    }
    if !runtime.auth_offboarding.may_publish(pending.generation) {
        return Err("Sign-in was canceled; start sign-in again.".to_string());
    }
    let outcome = async {
        runtime.ensure_login_matches_retained_pair(client.normalized_url(), &email)?;
        let outcome = client
            .continue_login(
                &email,
                &password,
                totp_code.as_deref(),
                recovery_code.as_deref(),
            )
            .await?;
        Ok::<_, DesktopError>((client, outcome))
    }
    .await;
    let (client, outcome) = outcome.map_err(user_error)?;
    let _publication = runtime.auth_publication.lock().await;
    if !runtime.auth_offboarding.may_publish(pending.generation) {
        retire_canceled_login(&runtime, &client, &outcome)
            .await
            .map_err(user_error)?;
        return Err("Sign-in was canceled by a newer sign-in or disconnect.".to_string());
    }
    match outcome {
        LoginOutcome::Authenticated {
            bearer_token,
            account_email,
            session_id,
            expires_at,
            ..
        } => {
            publish_authenticated_session(
                &runtime,
                &client,
                &bearer_token,
                &account_email,
                &session_id,
                expires_at,
                pending.generation,
            )
            .await
            .map_err(user_error)?;
            update_tray(&app, &runtime);
            Ok(LoginReply {
                kind: "authenticated",
                account_email,
            })
        }
        LoginOutcome::RequiresSecondFactor { account_email } => Err(format!(
            "Drive still requires a second factor for {}. Enter one current code.",
            account_email
        )),
    }
}

#[tauri::command]
async fn set_paused(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
    paused: bool,
) -> Result<DesktopView, String> {
    persist_paused_state(&runtime, paused)
        .await
        .map_err(user_error)?;
    update_tray(&app, &runtime);
    Ok(runtime.view())
}

#[tauri::command]
async fn disconnect(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
) -> Result<DesktopView, String> {
    disconnect_cleanup::disconnect(app, runtime).await
}

/// Execute the same confirmation-bound review action as the native UI.
/// The desktop-agent adapter obtains its confirmation through the shared
/// preparation path. Renderer IPC requires an independent native dialog in
/// application::review before it can reach this executor.
pub(crate) async fn choose_review_action_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    review_id: String,
    action: ReviewAction,
    confirmation_id: String,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(user_error)?;
    let confirmation = runtime
        .pending_review_confirmation
        .lock()
        .expect("review confirmation lock")
        .take()
        .ok_or_else(|| {
            "Review that exact deletion action once more before confirming.".to_string()
        })?;
    if confirmation.id != confirmation_id
        || confirmation.review_id != review_id
        || confirmation.action != action
        || confirmation.expires_at <= Utc::now()
    {
        return Err("The review confirmation expired or did not match this action.".to_string());
    }
    // A confirmed UI button never authorizes a stale role. Refresh root
    // discovery before reserving the executor, then validate the exact
    // manifest again inside review_execution immediately before any Drive
    // mutation.
    if let Err(error) = root_sync::refresh_authorized_roots(runtime).await {
        if matches!(error, DesktopError::NeedsReconnect) {
            update_tray(app, runtime);
            return Ok(runtime.view());
        }
        return Err(user_error(error));
    }
    // Capture the profile only after reserving the run. A concurrent
    // location switch either completed before this point and invalidates
    // the confirmation below, or is rejected while this action runs.
    let mut action_run = runtime.coordinator.begin_run().map_err(user_error)?;
    let state = action_run.state().clone();
    if state.pair.as_ref().map(sync_pair_id).as_deref() != Some(&confirmation.pair_id) {
        return Err(
                "The selected Drive location changed after confirmation. Recheck it and confirm the current item again."
                    .to_string(),
            );
    }
    let item = state
        .reviews
        .iter()
        .find(|item| item.id == review_id)
        .cloned()
        .ok_or_else(|| "That review item is no longer pending.".to_string())?;
    if review_confirmation_fingerprint(&state, &item).map_err(user_error)?
        != confirmation.fingerprint
    {
        return Err(
            "The review changed after confirmation. Recheck it and confirm the current item again."
                .to_string(),
        );
    }
    let decision = resolve_review_decision(&item, action).map_err(user_error)?;
    // Retiring an access-removed root is deliberately local-only. All
    // other reviews require the normal pair credential before they can
    // contact Drive.
    let captured_session = if decision != ReviewDecision::RemoveRetainedRoot {
        runtime.require_pair_credential().map_err(user_error)?;
        let session = runtime.current_session().map_err(user_error)?;
        let bearer = runtime.current_token(&session).map_err(user_error)?;
        Some((session, bearer))
    } else {
        None
    };
    update_tray(app, runtime);
    let mut cycle_budget = SyncCycleBudget::new(SyncPassLimits::default());
    let execution = match tokio::time::timeout(
            MAX_DESKTOP_SYNC_PASS_DURATION,
            shellx_drive_desktop_core::with_cycle_read_budget(
                shellx_drive_desktop_core::sync_cycle_local_read_limit(),
                execute_review_decision(
                &state,
                &item,
                decision,
                captured_session.as_ref().map(|(session, _)| session),
                captured_session.as_ref().map(|(_, bearer)| bearer.as_str()),
                &mut cycle_budget,
            )),
        )
        .await
        {
            Ok(execution) => execution,
            Err(_) => Err(DesktopError::InvalidState(
                "The reviewed recovery action exceeded its execution time limit; its state will be rechecked before retrying."
                    .to_string(),
            )),
        };
    let execution = if let Some((session, bearer)) = captured_session.as_ref() {
        admit_user_session_response(runtime, session, bearer, execution).await
    } else {
        execution
    };
    let execution = match execution {
        Err(DesktopError::NeedsReconnect) => {
            update_tray(app, runtime);
            return Ok(runtime.view());
        }
        Err(error) => return Err(user_error(error)),
        Ok(execution) => execution,
    };
    if let ReviewExecution::RetainedRootMoved { recovery } = execution {
        let pair = state
            .pair
            .clone()
            .ok_or_else(|| user_error(DesktopError::NeedsSetup))?;
        let mut next = state.clone();
        next.remove_pair(&confirmation.pair_id)
            .map_err(user_error)?;
        if let Err(error) = runtime.store.save(&next) {
            return match review_execution::restore_retained_root_after_state_failure(
                &pair, &recovery,
            ) {
                Ok(()) => Err(user_error(error)),
                Err(rollback_error) => Err(format!(
                    "The retained root moved to {} but its state removal could not be saved ({error}) and rollback also failed ({rollback_error}). Local bytes were not deleted.",
                    recovery.display()
                )),
            };
        }
        runtime.coordinator.append_activity(ActivityEntry {
            at: Utc::now(),
            direction: "Review".to_string(),
            relative_path: item.relative_path.clone(),
            result: review_action_result(decision).to_string(),
        });
        action_run.finish_state(next);
        invalidate_pending_confirmation(runtime);
        update_tray(app, runtime);
        return Ok(runtime.view());
    }
    runtime.coordinator.append_activity(ActivityEntry {
        at: Utc::now(),
        direction: "Review".to_string(),
        relative_path: item.relative_path.clone(),
        result: review_action_result(decision).to_string(),
    });
    runtime.save().map_err(user_error)?;
    // A decision never updates the baseline by itself. A planning-only
    // recheck remains inside the same reserved pair. A transient manifest
    // failure leaves the review available for a later retry.
    invalidate_pending_confirmation(runtime);
    recheck_reviews_with_budget(app, runtime, action_run, &mut cycle_budget).await
}

fn review_action_result(decision: ReviewDecision) -> &'static str {
    match decision {
        ReviewDecision::TrashRemote => "Moved the Drive item to trash; verifying the mirror.",
        ReviewDecision::RestoreLocal => "Restored the Drive copy locally; verifying the mirror.",
        ReviewDecision::RecoverLocal => {
            "Moved the local copy to the recovery area; verifying the mirror."
        }
        ReviewDecision::RestoreRemote => {
            "Restored the Drive item from trash; verifying the mirror."
        }
        ReviewDecision::RemoveRetainedRoot => {
            "Moved the retained local Drive root to recovery; Drive was not contacted."
        }
    }
}

fn baseline_for_review<'a>(
    state: &'a DesktopState,
    item: &ReviewItem,
) -> CoreResult<&'a BaselineEntry> {
    state
        .baseline
        .values()
        .find(|entry| entry.relative_path == item.relative_path)
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "the review no longer maps to a saved mirror baseline".to_string(),
            )
        })
}

fn current_baseline_remote<'a>(
    remote: &'a [RemoteEntry],
    baseline: &BaselineEntry,
) -> CoreResult<&'a RemoteEntry> {
    remote
        .iter()
        .find(|entry| entry.id == baseline.remote_id && !entry.trashed)
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "Drive no longer has the reviewed item; no remote mutation was attempted"
                    .to_string(),
            )
        })
}

fn remote_matches_baseline(remote: &RemoteEntry, baseline: &BaselineEntry) -> bool {
    let expected_kind = if baseline.kind.eq_ignore_ascii_case("folder") {
        RemoteEntryKind::Folder
    } else {
        RemoteEntryKind::File
    };
    remote.kind == expected_kind
        && remote.revision == baseline.revision
        && remote.content_hash == baseline.content_hash
}

async fn restore_local_tree(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    state: &DesktopState,
    item: &ReviewItem,
    remote: &[RemoteEntry],
    cycle_budget: &mut SyncCycleBudget,
) -> CoreResult<()> {
    ensure_tree_has_no_links(&pair.local_root)?;
    let paths = map_remote_paths(remote, pair.remote_root_id.as_deref())?;
    let mut entries = state
        .baseline
        .values()
        .filter(|entry| {
            entry.relative_path == item.relative_path
                || entry.relative_path.starts_with(&item.relative_path)
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return Err(DesktopError::InvalidState(
            "the reviewed local deletion has no saved restore tree".to_string(),
        ));
    }
    // Validate the complete tree and every local destination before any
    // download starts. Bodies then stage outside the pair and publish as
    // one final move, so a failed file never occupies the mirror root.
    let limits = SyncPassLimits::default();
    let mut restore_downloads = 0usize;
    let mut restore_bytes = 0u64;
    for entry in &entries {
        let live = current_baseline_remote(remote, entry)?;
        if !remote_matches_baseline(live, entry)
            || paths.get(&entry.remote_id) != Some(&entry.relative_path)
        {
            return Err(DesktopError::InvalidState(
                "Drive changed this restore tree after review; no local bytes were overwritten"
                    .to_string(),
            ));
        }
        if local_target(&pair.local_root, &entry.relative_path)?.exists() {
            return Err(DesktopError::InvalidState(format!(
                "local restore destination is occupied: {}",
                entry.relative_path.display()
            )));
        }
        if entry.kind.eq_ignore_ascii_case("file") {
            restore_downloads = restore_downloads.checked_add(1).ok_or_else(|| {
                DesktopError::InvalidState("restore download count overflowed".to_string())
            })?;
            restore_bytes = restore_bytes
                .checked_add(remote_download_size(live)?)
                .ok_or_else(|| {
                    DesktopError::InvalidState("restore download byte count overflowed".to_string())
                })?;
        }
    }
    if restore_downloads > limits.max_downloads || restore_bytes > limits.max_download_bytes {
        return Err(DesktopError::InvalidState(
            "reviewed restore exceeds the desktop aggregate download budget".to_string(),
        ));
    }
    cycle_budget.admit_extra(
        entries.len(),
        restore_downloads,
        restore_bytes,
        restore_downloads,
    )?;

    let staging_root = restore_staging_root(&pair.local_root)?;
    let (staging_area, batch) =
        create_owned_staging_batch(&pair.local_root, &staging_root, "restore")?;
    let staged_payload = batch.join("payload");
    let destination = local_target(&pair.local_root, &item.relative_path)?;
    let destination_boundary = capture_local_operation_boundary(&pair.local_root, &destination)?;

    entries.sort_by_key(|entry| {
        (
            if entry.kind.eq_ignore_ascii_case("folder") {
                0
            } else {
                1
            },
            entry.relative_path.components().count(),
        )
    });
    let staged_result = async {
        for entry in entries {
            let relative = entry
                .relative_path
                .strip_prefix(&item.relative_path)
                .map_err(|_| {
                    DesktopError::InvalidState(
                        "the reviewed restore tree has an invalid descendant path".to_string(),
                    )
                })?;
            let live = current_baseline_remote(remote, entry)?;
            if entry.kind.eq_ignore_ascii_case("folder") {
                let staged_directory = if relative.as_os_str().is_empty() {
                    staged_payload.clone()
                } else {
                    staged_payload.join(relative)
                };
                let staged_relative = staged_directory.strip_prefix(&batch).map_err(|_| {
                    DesktopError::UnsafePath(
                        "restore staging directory escapes its owned batch".to_string(),
                    )
                })?;
                ensure_local_directory(&batch, staged_relative)?;
            } else if entry.kind.eq_ignore_ascii_case("file") {
                let staged_file = if relative.as_os_str().is_empty() {
                    staged_payload.clone()
                } else {
                    staged_payload.join(relative)
                };
                let verified = write_remote_body_to_path(
                    client,
                    token,
                    &staging_area,
                    &batch,
                    &staged_file,
                    RemoteBodySpec {
                        remote_id: &entry.remote_id,
                        expected_hash: live.content_hash.as_deref(),
                        expected_size: remote_download_size(live)?,
                    },
                )
                .await?;
                drop(verified);
            } else {
                return Err(DesktopError::InvalidState(
                    "the saved restore tree has an unknown item kind".to_string(),
                ));
            }
        }
        // Keep the protected batch and every ancestor pinned before its
        // final DACL check. The pins deny delete sharing through the
        // directory publication, so a hostile parent cannot replace an
        // empty batch in the validation-to-rename window.
        let _restore_batch_pins = pin_absolute_directory_chain(&batch)?;
        staging_area.validate_for_publication(&batch)?;
        ensure_tree_has_no_links(&batch)?;
        verify_local_operation_boundary(&destination_boundary)?;
        if destination.exists() {
            return Err(DesktopError::InvalidState(format!(
                "local restore destination became occupied: {}",
                item.relative_path.display()
            )));
        }
        move_existing_entry_by_verified_parent(
            &batch,
            &staged_payload,
            &destination,
            &pair.local_root,
            || {
                verify_local_operation_boundary(&destination_boundary)?;
                if destination.exists() {
                    return Err(DesktopError::InvalidState(format!(
                        "local restore destination became occupied: {}",
                        item.relative_path.display()
                    )));
                }
                Ok(())
            },
        )
    }
    .await;
    if staged_result.is_err() {
        let _ = retire_owned_staging_batch(&staging_area, &batch);
    } else if let Err(error) = retire_owned_staging_batch(&staging_area, &batch) {
        return Err(error);
    }
    staged_result
}

fn move_local_to_recovery(
    pair: &SyncPair,
    state: &DesktopState,
    item: &ReviewItem,
) -> CoreResult<PathBuf> {
    move_local_to_recovery_before_native(pair, state, item, || Ok(()))
}

/// The extra closure is a deterministic test seam that runs only after
/// the source/destination ancestry handles are pinned but before the
/// handle-relative recovery rename. Production passes a no-op; tests use
/// it to prove a post-review edit or new descendant is rechecked and left
/// in place rather than being hidden in recovery.
fn move_local_to_recovery_before_native<F>(
    pair: &SyncPair,
    state: &DesktopState,
    item: &ReviewItem,
    before_native: F,
) -> CoreResult<PathBuf>
where
    F: FnOnce() -> CoreResult<()>,
{
    let local = checked_recovery_local_entries(pair, state, item)?;
    let affected = local
        .iter()
        .filter(|entry| {
            entry.relative_path == item.relative_path
                || entry.relative_path.starts_with(&item.relative_path)
        })
        .count();
    if affected == 0 {
        return Err(DesktopError::InvalidState(
            "the reviewed local item is already absent; nothing was moved".to_string(),
        ));
    }
    if affected.saturating_sub(1) != item.descendant_count {
        return Err(DesktopError::InvalidState(
            "the local descendant count changed after confirmation; review again before moving it"
                .to_string(),
        ));
    }
    let source = local_target(&pair.local_root, &item.relative_path)?;
    let parent = pair.local_root.parent().ok_or_else(|| {
        DesktopError::UnsafePath(
            "the selected local root has no parent for a recovery area".to_string(),
        )
    })?;
    let recovery_root = parent.join(".shellx-drive-recovery");
    if recovery_root.starts_with(&pair.local_root) {
        return Err(DesktopError::UnsafePath(
            "recovery area must stay outside the paired root".to_string(),
        ));
    }
    ensure_private_staging_directory(&recovery_root)?;
    ensure_tree_has_no_links(&recovery_root)?;
    let review_label = item
        .id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect::<String>();
    let batch = recovery_root.join(format!(
        "{}-{}",
        Utc::now().format("%Y%m%d-%H%M%S"),
        if review_label.is_empty() {
            "review"
        } else {
            &review_label
        }
    ));
    let destination = batch.join(&item.relative_path);
    if batch.exists() || destination.exists() {
        return Err(DesktopError::InvalidState(
            "the recovery batch or destination is already occupied; local bytes were left in place"
                .to_string(),
        ));
    }
    ensure_private_staging_directory(&batch)?;
    // Pin the new private batch (and its parent chain) before revalidating
    // it. Keep the no-delete handles alive while creating its destination
    // parents and through the handle-relative recovery rename.
    let _recovery_batch_pins = pin_absolute_directory_chain(&batch)?;
    ensure_private_staging_directory(&recovery_root)?;
    ensure_private_staging_directory(&batch)?;
    ensure_local_parent(&destination)?;
    ensure_tree_has_no_links(&recovery_root)?;
    // The recovery folder is a sibling of the pair root, intentionally on
    // the same volume. Bind the move to checked source and destination
    // parent handles so a pathname junction swap cannot redirect recovery
    // bytes outside this app-created batch. The callback's exact re-scan
    // is deliberately after those handles are pinned and immediately
    // before SetFileInformationByHandle.
    move_existing_entry_by_verified_parent(
        &pair.local_root,
        &source,
        &destination,
        &recovery_root,
        || {
            before_native()?;
            let _ = checked_recovery_local_entries(pair, state, item)?;
            Ok(())
        },
    )?;
    Ok(destination)
}

fn checked_recovery_local_entries(
    pair: &SyncPair,
    state: &DesktopState,
    item: &ReviewItem,
) -> CoreResult<Vec<LocalEntry>> {
    ensure_tree_has_no_links(&pair.local_root)?;
    let mut local = scan_local_tree(&pair.local_root)?;
    for entry in local.iter_mut().filter(|entry| entry.is_directory) {
        entry.directory_identity = Some(capture_directory_identity(
            &pair.local_root,
            &entry.relative_path,
        )?);
    }
    reviewed_local_subtree_matches_baseline(item, &state.baseline, &local)?;
    Ok(local)
}

/// Capture directory identity only after the ordinary core scanner has
/// rejected links and incompatible paths. `FILE_FLAG_OPEN_REPARSE_POINT`
/// plus a second operation-boundary check keeps a path swap from being
/// mistaken for a stable directory identity.
#[cfg(test)]
fn inspect_local_tree_with_directory_identities(
    root: &Path,
) -> CoreResult<shellx_drive_desktop_core::LocalTreeInspection> {
    let mut read_budget = local_read_budget_for_sync_pass();
    inspect_local_tree_with_directory_identities_with_budget(root, &mut read_budget)
}

fn inspect_local_tree_with_directory_identities_with_budget(
    root: &Path,
    read_budget: &mut ReadBudget,
) -> CoreResult<shellx_drive_desktop_core::LocalTreeInspection> {
    let mut inspection = inspect_local_tree_with_budget(root, read_budget)?;
    for entry in inspection
        .entries
        .iter_mut()
        .filter(|entry| entry.is_directory)
    {
        entry.directory_identity = Some(capture_directory_identity(root, &entry.relative_path)?);
    }
    Ok(inspection)
}

fn inspect_local_tree_with_directory_identities_with_budget_and_cancellation(
    root: &Path,
    read_budget: &mut ReadBudget,
    run: &SyncRun,
) -> CoreResult<shellx_drive_desktop_core::LocalTreeInspection> {
    let mut inspection =
        inspect_local_tree_with_budget_and_cancellation(root, read_budget, || {
            run.ensure_not_cancelled()
        })?;
    for entry in inspection
        .entries
        .iter_mut()
        .filter(|entry| entry.is_directory)
    {
        run.ensure_not_cancelled()?;
        entry.directory_identity = Some(capture_directory_identity(root, &entry.relative_path)?);
    }
    Ok(inspection)
}

fn capture_directory_identity(
    root: &Path,
    relative_path: &Path,
) -> CoreResult<WindowsDirectoryIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let target = local_target(root, relative_path)?;
    let boundary = capture_local_operation_boundary(root, &target)?;
    let file = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&target)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() {
        return Err(DesktopError::InvalidState(format!(
            "directory identity was requested for a non-directory: {}",
            relative_path.display()
        )));
    }
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(target));
    }
    let mut info = FILE_ID_INFO::default();
    // `FileIdInfo` returns the volume serial plus FILE_ID_128 from this
    // already-open, no-reparse directory handle.
    let success = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            &mut info as *mut FILE_ID_INFO as *mut std::ffi::c_void,
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if success == 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    verify_local_operation_boundary(&boundary)?;
    Ok(WindowsDirectoryIdentity::windows(
        info.VolumeSerialNumber,
        info.FileId.Identifier,
    ))
}

// Keep cancellation and filesystem authority explicit at the dispatch boundary.
#[allow(clippy::too_many_arguments)]
async fn execute_conflict_copies(
    run: &SyncRun,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    remote: &[RemoteEntry],
    actions: &[SyncAction],
    reviews: &mut [ReviewItem],
    local_read_budget: &mut ReadBudget,
) -> CoreResult<()> {
    let by_id = remote
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<HashMap<_, _>>();
    for action in actions {
        run.ensure_not_cancelled()?;
        let SyncAction::WriteRemoteConflictCopy {
            remote_id,
            conflict_path,
            ..
        } = action
        else {
            continue;
        };
        let remote = by_id.get(remote_id.as_str()).ok_or_else(|| {
            DesktopError::InvalidState("conflict source disappeared before download".to_string())
        })?;
        validate_planned_conflict_copy_review(reviews, conflict_path)?;
        let publication = write_remote_body(
            client,
            token,
            &pair.local_root,
            conflict_path,
            RemoteBodySpec {
                remote_id,
                expected_hash: remote.content_hash.as_deref(),
                expected_size: remote_download_size(remote)?,
            },
            &DownloadPrecondition::Absent,
            local_read_budget,
        )
        .await?;
        run.ensure_not_cancelled()?;
        merge_conflict_copy_publication_review(reviews, conflict_path, publication)?;
    }
    Ok(())
}

// Keep cancellation and filesystem authority explicit at the dispatch boundary.
#[allow(clippy::too_many_arguments)]
async fn execute_non_delete_actions(
    run: &SyncRun,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    sync_root: &SyncRoot,
    remote: &[RemoteEntry],
    plan: &ReconcilePlan,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<NonDeleteExecution> {
    ensure_tree_has_no_links(&pair.local_root)?;
    let mut folder_ids = remote_folder_ids(remote, &plan.remote_paths);
    let by_id = remote
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let mut actions = plan.actions.clone();
    actions.sort_by_key(|action| {
        (
            action_rank(action),
            action_path(action).components().count(),
        )
    });

    for action in actions {
        run.ensure_not_cancelled()?;
        match action {
            SyncAction::EnsureLocalDirectory { relative_path, .. } => {
                ensure_local_directory(&pair.local_root, &relative_path)?;
            }
            SyncAction::Download {
                remote_id,
                relative_path,
                precondition,
                ..
            } => {
                let remote = by_id.get(remote_id.as_str()).ok_or_else(|| {
                    DesktopError::InvalidState(
                        "download source disappeared before transfer".to_string(),
                    )
                })?;
                match write_remote_body(
                    client,
                    token,
                    &pair.local_root,
                    &relative_path,
                    RemoteBodySpec {
                        remote_id: &remote_id,
                        expected_hash: remote.content_hash.as_deref(),
                        expected_size: remote_download_size(remote)?,
                    },
                    &precondition,
                    local_read_budget,
                )
                .await?
                {
                    DownloadPublication::Published => {}
                    DownloadPublication::NeedsReview { review, .. } => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![review]));
                    }
                }
            }
            SyncAction::UploadNew {
                relative_path,
                is_directory,
                local: planned_local,
            } => {
                let path = local_target(&pair.local_root, &relative_path)?;
                let parent_id = remote_parent_id(pair, &folder_ids, &relative_path)?;
                let name = local_leaf_name(&relative_path)?;
                ensure_local_operation_boundary(&pair.local_root, &path)?;
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.is_dir() != is_directory {
                    return Err(DesktopError::InvalidState(format!(
                        "local entry changed type before upload: {}",
                        relative_path.display()
                    )));
                }
                if is_directory {
                    let created = with_current_pair_remote_mutation(run.state(), pair, || async {
                        client
                            .create_folder(token, &pair.workspace_id, parent_id.as_deref(), name)
                            .await
                    })
                    .await?;
                    if !created_remote_response_matches(
                        &created,
                        &pair.workspace_id,
                        parent_id.as_deref(),
                        name,
                        RemoteFileKind::Folder,
                        None,
                    ) {
                        return Err(DesktopError::InvalidState(
                            "Drive did not return the exact folder created by this sync pass"
                                .to_string(),
                        ));
                    }
                    folder_ids.insert(relative_path, created.id);
                } else {
                    let snapshot = match snapshot_upload_source(
                        &pair.local_root,
                        &relative_path,
                        local_read_budget,
                    ) {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            return Ok(NonDeleteExecution::NeedsReview(vec![
                                upload_snapshot_failure_review(&relative_path, &error),
                            ]));
                        }
                    };
                    if let Some(result) = plan_gate(&planned_local, &snapshot) {
                        return Ok(result);
                    }
                    if !upload_source_still_matches(&pair.local_root, &snapshot, local_read_budget)
                        .unwrap_or(false)
                    {
                        let _ = retire_upload_snapshot(&snapshot);
                        return Ok(NonDeleteExecution::NeedsReview(vec![
                            upload_source_race_review(&relative_path),
                        ]));
                    }
                    let transfer = with_current_pair_remote_mutation(run.state(), pair, || async {
                        client
                            .upload_new_file_from_reader(
                                token,
                                &pair.workspace_id,
                                parent_id.as_deref(),
                                name,
                                open_upload_snapshot(&snapshot)?,
                                snapshot.local.size_bytes,
                            )
                            .await
                    })
                    .await;
                    let still_matches =
                        upload_source_still_matches(&pair.local_root, &snapshot, local_read_budget);
                    let snapshot_matches = verify_upload_snapshot(&snapshot);
                    let cleanup = retire_upload_snapshot(&snapshot);
                    let published = transfer?;
                    if !still_matches.unwrap_or(false)
                        || !snapshot_matches.unwrap_or(false)
                        || cleanup.is_err()
                        || !created_remote_response_matches(
                            &published,
                            &pair.workspace_id,
                            parent_id.as_deref(),
                            name,
                            RemoteFileKind::File,
                            snapshot.local.content_hash.as_deref(),
                        )
                    {
                        return Ok(NonDeleteExecution::NeedsReview(vec![
                            upload_source_race_review(&relative_path),
                        ]));
                    }
                }
            }
            SyncAction::UploadExisting {
                remote_id,
                relative_path,
                base_revision,
                local: planned_local,
            } => {
                let source = match by_id.get(remote_id.as_str()) {
                    Some(source)
                        if source.revision == base_revision
                            && !source.trashed
                            && source.kind == RemoteEntryKind::File =>
                    {
                        *source
                    }
                    _ => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![
                            replacement_conflict_review(&remote_id, &relative_path),
                        ]));
                    }
                };
                let snapshot = match snapshot_upload_source(
                    &pair.local_root,
                    &relative_path,
                    local_read_budget,
                ) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![
                            upload_snapshot_failure_review(&relative_path, &error),
                        ]));
                    }
                };
                if let Some(result) = plan_gate(&planned_local, &snapshot) {
                    return Ok(result);
                }
                if !upload_source_still_matches(&pair.local_root, &snapshot, local_read_budget)
                    .unwrap_or(false)
                {
                    let _ = retire_upload_snapshot(&snapshot);
                    return Ok(NonDeleteExecution::NeedsReview(vec![
                        upload_source_race_review(&relative_path),
                    ]));
                }
                let transfer = with_current_pair_remote_mutation(run.state(), pair, || async {
                    client
                        .replace_existing_file_from_reader(
                            token,
                            &remote_id,
                            base_revision,
                            open_upload_snapshot(&snapshot)?,
                            snapshot.local.size_bytes,
                        )
                        .await
                })
                .await;
                let still_matches =
                    upload_source_still_matches(&pair.local_root, &snapshot, local_read_budget);
                let snapshot_matches = verify_upload_snapshot(&snapshot);
                let cleanup = retire_upload_snapshot(&snapshot);
                let transfer = transfer?;
                if !still_matches.unwrap_or(false)
                    || !snapshot_matches.unwrap_or(false)
                    || cleanup.is_err()
                {
                    return Ok(NonDeleteExecution::NeedsReview(vec![
                        upload_source_race_review(&relative_path),
                    ]));
                }
                match transfer {
                    ExistingFileTransfer::Updated(updated)
                        if updated_remote_response_matches(
                            &updated,
                            &remote_id,
                            &pair.workspace_id,
                            base_revision,
                            source,
                            snapshot.local.content_hash.as_deref(),
                            snapshot.local.size_bytes,
                        ) => {}
                    ExistingFileTransfer::Updated(_) => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![
                            replacement_conflict_review(&remote_id, &relative_path),
                        ]));
                    }
                    ExistingFileTransfer::Conflict => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![
                            replacement_conflict_review(&remote_id, &relative_path),
                        ]));
                    }
                    ExistingFileTransfer::UnsupportedResumableReplacement {
                        size_bytes, ..
                    } => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![
                            unsupported_replacement_review(&remote_id, &relative_path, size_bytes),
                        ]));
                    }
                }
            }
            SyncAction::MoveRemote {
                remote_id,
                to,
                base_revision,
                folder_precondition,
                ..
            } => {
                let source = match by_id.get(remote_id.as_str()) {
                    Some(source)
                        if source.revision == base_revision
                            && matches!(
                                (&source.kind, folder_precondition.is_some()),
                                (RemoteEntryKind::File, false) | (RemoteEntryKind::Folder, true)
                            ) =>
                    {
                        source
                    }
                    _ => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![remote_move_review(
                            &to,
                            "Drive changed, removed, or changed the kind of the tracked item before its rename could be sent.",
                        )]));
                    }
                };
                if let Some(folder_precondition) = folder_precondition.as_ref() {
                    if !folder_move_source_still_matches_with_budget(
                        &pair.local_root,
                        &to,
                        folder_precondition,
                        local_read_budget,
                    )
                    .unwrap_or(false)
                    {
                        return Ok(NonDeleteExecution::NeedsReview(vec![
                            remote_folder_move_review(&to, folder_precondition),
                        ]));
                    }
                }
                let parent_id = match remote_parent_id(pair, &folder_ids, &to) {
                    Ok(parent_id) => parent_id,
                    Err(_) => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![remote_move_review(
                            &to,
                            "The renamed local file has no verified Drive destination folder.",
                        )]));
                    }
                };
                let name = match local_leaf_name(&to) {
                    Ok(name) => name,
                    Err(_) => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![remote_move_review(
                            &to,
                            "The renamed local file has no valid Drive destination path.",
                        )]));
                    }
                };
                match with_current_pair_remote_mutation(run.state(), pair, || async {
                    client
                        .move_remote_file(
                            token,
                            &remote_id,
                            base_revision,
                            parent_id.as_deref(),
                            name,
                        )
                        .await
                })
                .await?
                {
                    RemoteMoveTransfer::Moved(moved)
                        if remote_move_response_matches(
                            &moved,
                            &remote_id,
                            &pair.workspace_id,
                            base_revision,
                            parent_id.as_deref(),
                            name,
                        ) => {}
                    RemoteMoveTransfer::Moved(_) => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![remote_move_review(
                            &to,
                            "Drive did not return the exact tracked file, revision, and destination path for this rename.",
                        )]));
                    }
                    RemoteMoveTransfer::Conflict => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![remote_move_review(
                            &to,
                            "Drive changed the tracked file before this rename could be applied.",
                        )]));
                    }
                    RemoteMoveTransfer::NeedsReview => {
                        return Ok(NonDeleteExecution::NeedsReview(vec![remote_move_review(
                            &to,
                            "Drive rejected or could not verify this rename destination.",
                        )]));
                    }
                }
                // Folder moves PATCH only their root metadata. Drive keeps
                // the same folder ID and therefore child IDs/history/shares.
                debug_assert!(matches!(
                    (&source.kind, folder_precondition.is_some()),
                    (RemoteEntryKind::File, false) | (RemoteEntryKind::Folder, true)
                ));
                if let Some(folder_precondition) = folder_precondition.as_ref() {
                    // The PATCH already moved the remote root. Recheck the
                    // complete local subtree before any planned child body
                    // action or final baseline can bind a late local edit
                    // to that remote identity.
                    let still_matches = folder_move_source_still_matches_with_budget(
                        &pair.local_root,
                        &to,
                        folder_precondition,
                        local_read_budget,
                    )
                    .unwrap_or(false);
                    if let NonDeleteExecution::NeedsReview(reviews) =
                        finish_outbound_folder_move_postpatch(
                            &to,
                            folder_precondition,
                            still_matches,
                        )
                    {
                        return Ok(NonDeleteExecution::NeedsReview(reviews));
                    }
                }
            }
            SyncAction::MoveLocal {
                from,
                to,
                precondition,
                folder_precondition,
                ..
            } => {
                if let Some(folder_precondition) = folder_precondition.as_ref() {
                    // A folder move mutates the whole local subtree in one
                    // native operation. Re-fetch Drive immediately before
                    // that operation; a planned manifest is not a lease.
                    let preflight_matches = inbound_folder_remote_witness_matches_now(
                        client,
                        token,
                        pair,
                        sync_root,
                        folder_precondition,
                    )
                    .await?;
                    let outcome = execute_inbound_folder_move_preflight(
                        &from,
                        &to,
                        folder_precondition,
                        preflight_matches,
                        || {
                            move_unchanged_local_folder_with_budget(
                                &pair.local_root,
                                &from,
                                &to,
                                &precondition,
                                folder_precondition,
                                local_read_budget,
                            )
                        },
                    )?;
                    if let NonDeleteExecution::NeedsReview(reviews) = outcome {
                        return Ok(NonDeleteExecution::NeedsReview(reviews));
                    }
                    let postflight_matches = inbound_folder_remote_witness_matches_now(
                        client,
                        token,
                        pair,
                        sync_root,
                        folder_precondition,
                    )
                    .await?;
                    if let NonDeleteExecution::NeedsReview(reviews) =
                        finish_inbound_folder_move_postflight(
                            &from,
                            &to,
                            folder_precondition,
                            postflight_matches,
                        )
                    {
                        return Ok(NonDeleteExecution::NeedsReview(reviews));
                    }
                } else {
                    let move_result = move_unchanged_local_path_with_budget(
                        &pair.local_root,
                        &from,
                        &to,
                        &precondition,
                        local_read_budget,
                    );
                    if move_result.is_err() {
                        return Ok(NonDeleteExecution::NeedsReview(vec![inbound_move_review(
                            &from, &to,
                        )]));
                    }
                }
            }
            SyncAction::WriteRemoteConflictCopy { .. } => {
                // Conflict copies are executed by the review branch only.
            }
        }
        run.ensure_not_cancelled()?;
    }
    Ok(NonDeleteExecution::Complete)
}

#[cfg(test)]
#[path = "../windows/inbound_publication_tests.rs"]
mod inbound_publication_tests;

#[cfg(test)]
#[path = "../windows/replacement_security_tests.rs"]
mod replacement_security_tests;

#[cfg(test)]
#[path = "../windows/hardlink_security_tests.rs"]
mod hardlink_security_tests;

pub fn run_from_args() -> i32 {
    app_shell::run_from_args()
}

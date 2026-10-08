//! macOS execution of confirmed, recoverable review actions.
//!
//! Local removal is always a descriptor-bound move to a private sibling
//! recovery batch. Remote mutations remain revision-bound and a folder
//! restore verifies its full saved subtree before admitting any local write.

use super::*;
use crate::application::sync_terminal::session::admit_user_session_response;
use chrono::Utc;
use shellx_drive_desktop_core::{
    resolve_review_decision, review_confirmation_fingerprint, DesktopError, DriveHttpClient,
    ReviewAction, ReviewDecision,
};
use tauri::Manager;

mod mutations;
mod recovery;
mod restore;

pub(crate) async fn choose_review_action_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    review_id: String,
    action: ReviewAction,
    confirmation_id: String,
) -> Result<DesktopView, String> {
    sync::validate_connection_folders(app, runtime)
        .await
        .map_err(macos_error)?;
    let manager = app.state::<ConnectionManager>();
    let _permit = manager
        .acquire_sync_permit_for(runtime)
        .await
        .map_err(macos_error)?;
    runtime
        .require_candidate_recovery_complete()
        .map_err(macos_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(macos_error)?;
    let confirmation = runtime
        .pending_review_confirmation
        .lock()
        .expect("review confirmation lock")
        .take()
        .ok_or_else(|| "Review that exact action once more before confirming.".to_string())?;
    if confirmation.id != confirmation_id
        || confirmation.review_id != review_id
        || confirmation.action != action
        || confirmation.expires_at <= Utc::now()
    {
        return Err("The review confirmation expired or did not match this action.".to_string());
    }
    // Access-removed root retirement is deliberately local-only. It must not
    // require a still-valid server session or contact Drive before the
    // explicitly confirmed recovery move.
    let preliminary = runtime.coordinator.snapshot();
    let preliminary_item = preliminary
        .reviews
        .iter()
        .find(|item| item.id == review_id)
        .ok_or_else(|| "That review item is no longer pending.".to_string())?;
    let local_only = resolve_review_decision(preliminary_item, action).map_err(macos_error)?
        == ReviewDecision::RemoveRetainedRoot;
    if !local_only {
        if let Err(error) = pairing::refresh_authorized_roots(runtime).await {
            if matches!(error, DesktopError::NeedsReconnect) {
                shell::update_tray(app, runtime);
                return Ok(runtime.view());
            }
            return Err(macos_error(error));
        }
    }
    let mut operation = runtime
        .coordinator
        .begin_lifecycle_operation()
        .map_err(macos_error)?;
    let state = runtime.coordinator.snapshot();
    if state
        .pair
        .as_ref()
        .map(shellx_drive_desktop_core::sync_pair_id)
        .as_deref()
        != Some(&confirmation.pair_id)
    {
        return Err(
            "The selected Drive location changed after confirmation. Recheck and confirm the current item again."
                .to_string(),
        );
    }
    let item = state
        .reviews
        .iter()
        .find(|item| item.id == review_id)
        .cloned()
        .ok_or_else(|| "That review item is no longer pending.".to_string())?;
    if review_confirmation_fingerprint(&state, &item).map_err(macos_error)?
        != confirmation.fingerprint
    {
        return Err("The reviewed file changed. Recheck it and confirm again.".to_string());
    }
    let decision = resolve_review_decision(&item, action).map_err(macos_error)?;
    let pair = state
        .pair
        .clone()
        .ok_or_else(|| macos_error(DesktopError::NeedsSetup))?;
    let expected = pair.local_root_identity.as_ref().ok_or_else(|| {
        "This Drive folder has no macOS identity. Pair it again before reviewing files.".to_string()
    })?;
    let guard =
        crate::platform::unix::filesystem::UnixRootGuard::acquire(&pair.local_root, Some(expected))
            .map_err(macos_error)?;
    guard
        .require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(&pair))
        .map_err(macos_error)?;
    if decision == ReviewDecision::RemoveRetainedRoot {
        let recovery = recovery::remove_retained_root(&pair, &guard).map_err(macos_error)?;
        let mut candidate = state.clone();
        candidate
            .remove_pair(&confirmation.pair_id)
            .map_err(macos_error)?;
        candidate.append_activity(shellx_drive_desktop_core::ActivityEntry {
            at: Utc::now(),
            direction: "Review".to_string(),
            relative_path: item.relative_path.clone(),
            result: "Moved the retained local Drive root to recovery; Drive was not contacted."
                .to_string(),
        });
        if let Err(error) = runtime.store.save(&candidate) {
            let rollback = recovery::rollback_retained_root(&pair, &recovery);
            return match rollback {
                Ok(()) => Err(macos_error(error)),
                Err(rollback_error) => Err(format!(
                    "The retained Drive root moved to {} but its state removal could not be saved ({error}) and rollback also failed ({rollback_error}). Local bytes were not deleted.",
                    recovery.display()
                )),
            };
        }
        operation.finish_state(candidate);
        invalidate_pending_confirmation(runtime);
        shell::update_tray(app, runtime);
        return Ok(runtime.view());
    }
    let metadata = state
        .sync_root_for_pair(&pair)
        .ok_or_else(|| "This Drive location no longer has current root authority.".to_string())?;
    if !metadata.is_available_at(Utc::now()) {
        return Err("Drive access for this location has expired or was removed. Local files were left untouched.".to_string());
    }
    let session = runtime.current_session().map_err(macos_error)?;
    let token = runtime.current_token(&session).map_err(macos_error)?;
    let mut budget = shellx_drive_desktop_core::SyncCycleBudget::new(
        shellx_drive_desktop_core::SyncPassLimits::default(),
    );
    let client = DriveHttpClient::new(&session.server_url)
        .map_err(macos_error)?
        .with_cycle_budget(&budget);
    let manifest = match admit_user_session_response(
        runtime,
        &session,
        &token,
        client.sync_root_manifest(&token, &metadata.root).await,
    )
    .await
    {
        Err(DesktopError::NeedsReconnect) => {
            shell::update_tray(app, runtime);
            return Ok(runtime.view());
        }
        Err(error) => return Err(macos_error(error)),
        Ok(manifest) => manifest,
    };
    if !manifest.root.same_manifest_subject(&metadata.root)
        || !manifest.root.is_available_at(Utc::now())
    {
        return Err(
            "Drive root authority changed before this review action; no mutation was attempted."
                .to_string(),
        );
    }
    if matches!(
        decision,
        ReviewDecision::TrashRemote | ReviewDecision::RestoreRemote
    ) && !manifest.root.role.may_write()
    {
        return Err(
            "Drive root is now Viewer access; this review cannot change Drive.".to_string(),
        );
    }
    let remote = manifest
        .files
        .into_iter()
        .map(sync::remote_entry_for_review)
        .collect::<CoreResult<Vec<_>>>()
        .map_err(macos_error)?;
    // Review confirmation is a separate, serialized lifecycle operation. It
    // admits exactly one reviewed item under the same manifest envelope.
    budget.admit(&remote, &[]).map_err(macos_error)?;
    match admit_user_session_response(
        runtime,
        &session,
        &token,
        shellx_drive_desktop_core::with_cycle_read_budget(
            shellx_drive_desktop_core::sync_cycle_local_read_limit(),
            mutations::execute_decision(
                mutations::ConfirmedReviewInputs {
                    guard: &guard,
                    client: &client,
                    token: &token,
                    pair: &pair,
                    state: &state,
                    item: &item,
                    remote: &remote,
                    budget: &mut budget,
                },
                decision,
            ),
        )
        .await,
    )
    .await
    {
        Err(DesktopError::NeedsReconnect) => {
            shell::update_tray(app, runtime);
            return Ok(runtime.view());
        }
        Err(error) => return Err(macos_error(error)),
        Ok(()) => {}
    }
    let mut candidate = state;
    candidate.reviews.retain(|current| current.id != review_id);
    runtime.store.save(&candidate).map_err(macos_error)?;
    operation.finish_state(candidate);
    shell::update_tray(app, runtime);
    Ok(runtime.view())
}

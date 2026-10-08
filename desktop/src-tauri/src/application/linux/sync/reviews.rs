use super::*;

pub(crate) async fn choose_review_action_impl(
    app: &AppHandle,
    runtime: &Runtime,
    review_id: String,
    action: shellx_drive_desktop_core::ReviewAction,
    confirmation_id: String,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(present_error)?;
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
    if let Err(error) = roots::refresh_authorized_roots(runtime).await {
        if matches!(error, DesktopError::NeedsReconnect) {
            update_tray(app, runtime);
            return Ok(runtime.view());
        }
        return Err(present_error(error));
    }
    let mut run = runtime.coordinator.begin_run().map_err(present_error)?;
    let state = run.state().clone();
    if state.pair.as_ref().map(sync_pair_id).as_deref() != Some(&confirmation.pair_id) {
        return Err(
            "The active Drive location changed after confirmation. Recheck and confirm again."
                .to_string(),
        );
    }
    let item = state
        .reviews
        .iter()
        .find(|item| item.id == review_id)
        .cloned()
        .ok_or_else(|| "That review item is no longer pending.".to_string())?;
    if review_confirmation_fingerprint(&state, &item).map_err(present_error)?
        != confirmation.fingerprint
    {
        return Err(
            "The review changed after confirmation. Recheck and confirm again.".to_string(),
        );
    }
    let decision = resolve_review_decision(&item, action).map_err(present_error)?;
    let result = execute_review(runtime, &mut run, &item, decision).await;
    if let Ok(ReviewExecution::RetainedRootMoved { pair, recovery }) = &result {
        let mut next = run.state().clone();
        next.remove_pair(&confirmation.pair_id)
            .map_err(present_error)?;
        next.append_activity(ActivityEntry {
            at: Utc::now(),
            direction: "Review".to_string(),
            relative_path: item.relative_path.clone(),
            result: "Moved the retained local Drive root to recovery; Drive was not contacted."
                .to_string(),
        });
        if let Err(error) = runtime.store.save(&next) {
            let rollback = rollback_retained_root(pair, recovery);
            return match rollback {
                Ok(()) => Err(present_error(error)),
                Err(rollback_error) => Err(format!(
                    "The retained Drive root moved to {} but its state removal could not be saved ({error}) and rollback also failed ({rollback_error}). Local bytes were not deleted.",
                    recovery.display()
                )),
            };
        }
        run.finish_state(next);
        invalidate_pending_confirmation(runtime);
        return settle(app, runtime, Ok(()));
    }
    settle(app, runtime, result.map(|_| ()))
}

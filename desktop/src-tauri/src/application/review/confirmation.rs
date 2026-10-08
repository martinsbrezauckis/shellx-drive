use std::sync::atomic::Ordering;

use chrono::Utc;
use shellx_drive_desktop_core::{
    resolve_review_decision, review_confirmation_fingerprint, sync_pair_id, DesktopError,
    Result as CoreResult, ReviewAction,
};

use super::{ReviewConfirmation, Runtime};
use crate::application::runtime::PendingReviewConfirmation;

const REVIEW_CONFIRMATION_TTL_SECS: i64 = 5 * 60;

pub(crate) fn prepare_review_confirmation(
    runtime: &Runtime,
    review_id: String,
    action: ReviewAction,
) -> CoreResult<ReviewConfirmation> {
    runtime.require_candidate_recovery_complete()?;
    let state = runtime.coordinator.snapshot();
    let pair_id = state
        .pair
        .as_ref()
        .map(sync_pair_id)
        .ok_or(DesktopError::NeedsSetup)?;
    prepare_review_confirmation_for_pair(runtime, pair_id, review_id, action)
}

/// Agent actions name the exact configured location listed by DesktopView.
/// The dispatcher first switches through the ordinary guarded platform path,
/// then this verifies that no intervening state change substituted a review
/// from another root.
pub(crate) fn prepare_review_confirmation_for_pair(
    runtime: &Runtime,
    pair_id: String,
    review_id: String,
    action: ReviewAction,
) -> CoreResult<ReviewConfirmation> {
    runtime.require_candidate_recovery_complete()?;
    let state = runtime.coordinator.snapshot();
    if state.pair.as_ref().map(sync_pair_id).as_deref() != Some(pair_id.as_str()) {
        return Err(DesktopError::InvalidState(
            "the requested Drive location is no longer selected".to_string(),
        ));
    }
    let item = state
        .reviews
        .iter()
        .find(|item| item.id == review_id)
        .ok_or_else(|| {
            DesktopError::InvalidState("That review item is no longer pending.".to_string())
        })?;
    // Keep unsupported conflict/path actions queued. No confirmation must
    // imply an execution route that the native adapter does not have.
    resolve_review_decision(item, action)?;
    let fingerprint = review_confirmation_fingerprint(&state, item)?;
    let response_fingerprint = fingerprint.clone();
    let confirmation_id = format!(
        "review-{}-{}",
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        runtime
            .next_review_confirmation
            .fetch_add(1, Ordering::AcqRel)
            + 1,
    );
    *runtime
        .pending_review_confirmation
        .lock()
        .expect("review confirmation lock") = Some(PendingReviewConfirmation {
        id: confirmation_id.clone(),
        review_id,
        action,
        pair_id,
        fingerprint,
        expires_at: Utc::now() + chrono::Duration::seconds(REVIEW_CONFIRMATION_TTL_SECS),
    });
    Ok(ReviewConfirmation {
        confirmation_id,
        relative_path: item.relative_path.clone(),
        descendant_count: item.descendant_count,
        action,
        fingerprint: response_fingerprint,
    })
}

pub(crate) fn ensure_review_confirmation_pair(
    runtime: &Runtime,
    pair_id: &str,
    review_id: &str,
    action: ReviewAction,
    confirmation_id: &str,
    fingerprint: &str,
) -> CoreResult<()> {
    let active_pair_id = runtime
        .coordinator
        .snapshot()
        .pair
        .as_ref()
        .map(sync_pair_id)
        .ok_or(DesktopError::NeedsSetup)?;
    if active_pair_id != pair_id {
        return Err(DesktopError::InvalidState(
            "the requested Drive location is no longer selected".to_string(),
        ));
    }
    let pending = runtime
        .pending_review_confirmation
        .lock()
        .expect("review confirmation lock");
    let Some(pending) = pending.as_ref() else {
        return Err(DesktopError::InvalidState(
            "that review action is no longer pending confirmation".to_string(),
        ));
    };
    if pending.id != confirmation_id
        || pending.pair_id != pair_id
        || pending.review_id != review_id
        || pending.action != action
        || pending.fingerprint != fingerprint
        || pending.expires_at <= Utc::now()
    {
        return Err(DesktopError::InvalidState(
            "the review confirmation no longer matches the requested location, action, and witness"
                .to_string(),
        ));
    }
    Ok(())
}

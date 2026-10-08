use super::{AppState, STALE_UPLOAD_MAX_AGE_SECONDS};

pub(super) async fn reconcile_upload_parts_once(state: &AppState) {
    let Ok(mutation_permit) = state.try_mutation_permit() else {
        return;
    };
    let reaper_state = state.clone();
    let outcome = tokio::task::spawn_blocking(move || -> crate::error::ApiResult<_> {
        let _mutation_permit = mutation_permit;
        let uploads = crate::routes::uploads::cleanup::reconcile_terminal_upload_parts_lock_safe(
            &reaper_state,
            STALE_UPLOAD_MAX_AGE_SECONDS,
        )?;
        let drops =
            crate::routes::drop_uploads::cleanup::reconcile_terminal_drop_upload_parts_lock_safe(
                &reaper_state,
                STALE_UPLOAD_MAX_AGE_SECONDS,
            )?;
        Ok((uploads, drops))
    })
    .await;
    match outcome {
        Ok(Ok((uploads, drops))) if uploads.cleaned + drops.cleaned > 0 => tracing::info!(
            cleaned_uploads = uploads.cleaned,
            inspected_uploads = uploads.inspected,
            complete_uploads = uploads.complete,
            cleaned_drops = drops.cleaned,
            inspected_drops = drops.inspected,
            complete_drops = drops.complete,
            "reconciled terminal upload part batches"
        ),
        Ok(Ok(_)) => {}
        Ok(Err(error)) => tracing::warn!(%error, "terminal upload part reconciliation failed"),
        Err(join_error) => {
            tracing::warn!(%join_error, "terminal upload part reconciliation panicked")
        }
    }
}

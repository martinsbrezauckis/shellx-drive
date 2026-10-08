//! Serialized every-root reconciliation for the macOS desktop adapter.

use std::path::PathBuf;

use chrono::Utc;
use shellx_drive_desktop_core::{
    ActivityEntry, DesktopError, Result as CoreResult, SyncCycleBudget, SyncPassLimits,
    SyncRootAccessRemovalReason, SyncRun,
};

use crate::application::{
    sync_terminal::{
        session::{admit_persisted_all_roots, is_user_session_unauthorized},
        SyncCycleTerminal,
    },
    Runtime,
};
use crate::session_identity::SessionIdentity;

use super::{lifecycle, root_access_was_removed, sync_run};

/// Visit every root materialized under the one signed-in account while a
/// single coordinator reservation is held. The profile chosen in the UI is
/// restored before state publication, so it never filters background work.
pub(super) async fn sync_all_roots(
    runtime: &Runtime,
    run: &mut SyncRun,
    recheck_only: bool,
) -> CoreResult<()> {
    let session = runtime.current_session()?;
    let captured_bearer = runtime.current_token(&session)?;
    shellx_drive_desktop_core::with_cycle_read_budget(
        shellx_drive_desktop_core::sync_cycle_local_read_limit(),
        sync_all_roots_with_captured_session(
            runtime,
            run,
            recheck_only,
            &session,
            &captured_bearer,
        ),
    )
    .await
}

async fn sync_all_roots_with_captured_session(
    runtime: &Runtime,
    run: &mut SyncRun,
    recheck_only: bool,
    session: &SessionIdentity,
    captured_bearer: &str,
) -> CoreResult<()> {
    let selected_pair_id = run.selected_pair_id()?;
    let mut terminal = SyncCycleTerminal::default();
    let mut budget = SyncCycleBudget::new(SyncPassLimits::default());
    run.ensure_not_cancelled()?;
    for pair_id in run.cycle_pair_ids()? {
        run.ensure_not_cancelled()?;
        run.activate_configured_pair(&pair_id)?;
        if (recheck_only && !run.has_active_reviews())
            || (!recheck_only && run.has_active_reviews())
        {
            continue;
        }
        let pair = run.state().pair.clone().ok_or(DesktopError::NeedsSetup)?;
        match sync_run(run, recheck_only, session, captured_bearer, &mut budget).await {
            Ok(()) => (),
            Err(DesktopError::SyncCancelledForDisconnect) => {
                return Err(DesktopError::SyncCancelledForDisconnect);
            }
            Err(error) if is_user_session_unauthorized(&error) => {
                return admit_persisted_all_roots(
                    runtime,
                    run,
                    &selected_pair_id,
                    session,
                    captured_bearer,
                    error,
                )
                .await;
            }
            Err(error) if root_access_was_removed(&error) => {
                run.mark_active_root_removed(
                    SyncRootAccessRemovalReason::RevokedOrRemoved,
                    Utc::now(),
                )?;
                lifecycle::finish_stopped_root(run, &pair)?;
                run.append_active_activity(ActivityEntry {
                    at: Utc::now(),
                    direction: "Drive".to_string(),
                    relative_path: PathBuf::new(),
                    result:
                        "Access was removed during this sync; local files were retained for review."
                            .to_string(),
                });
            }
            Err(error @ DesktopError::SyncCycleBudgetExceeded(_)) => {
                terminal.record_budget_exhaustion(run, error);
                run.defer_cycle_after(&pair_id)?;
                break;
            }
            Err(error) => {
                terminal.record_root_failure(run, error);
            }
        }
        run.ensure_not_cancelled()?;
    }
    run.ensure_not_cancelled()?;
    let final_state = run.finalize_all_roots_state(&selected_pair_id)?;
    let result = terminal.finish(&final_state);
    run.finish_persisted_state(final_state, |state| runtime.store.save(state))?;
    result
}

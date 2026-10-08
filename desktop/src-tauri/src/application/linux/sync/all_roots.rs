//! Serialized every-root reconciliation for the Linux desktop adapter.
use shellx_drive_desktop_core::{
    DesktopError, ReadBudget, Result as CoreResult, SyncCycleBudget, SyncPassLimits, SyncRun,
};

use crate::application::{
    sync_terminal::{
        session::{admit_persisted_all_roots, is_user_session_unauthorized},
        SyncCycleTerminal,
    },
    Runtime,
};
use crate::session_identity::SessionIdentity;

use super::super::reconcile;
pub(super) async fn reconcile_all_roots(
    runtime: &Runtime,
    run: &mut SyncRun,
    recheck_only: bool,
) -> CoreResult<()> {
    let session = runtime.current_session()?;
    let captured_bearer = runtime.current_token(&session)?;
    shellx_drive_desktop_core::with_cycle_read_budget(
        shellx_drive_desktop_core::sync_cycle_local_read_limit(),
        reconcile_all_roots_with_captured_session(
            runtime,
            run,
            recheck_only,
            &session,
            &captured_bearer,
        ),
    )
    .await
}

async fn reconcile_all_roots_with_captured_session(
    runtime: &Runtime,
    run: &mut SyncRun,
    recheck_only: bool,
    session: &SessionIdentity,
    captured_bearer: &str,
) -> CoreResult<()> {
    let selected_pair_id = run.selected_pair_id()?;
    let mut terminal = SyncCycleTerminal::default();
    let mut cycle_budget = SyncCycleBudget::new(SyncPassLimits::default());
    let mut local_reads =
        ReadBudget::new_cycle(shellx_drive_desktop_core::sync_cycle_local_read_limit());
    for pair_id in run.cycle_pair_ids()? {
        run.ensure_not_cancelled()?;
        run.activate_configured_pair(&pair_id)?;
        if (recheck_only && !run.has_active_reviews())
            || (!recheck_only && run.has_active_reviews())
        {
            continue;
        }
        let pair = run.state().pair.clone().ok_or(DesktopError::NeedsSetup)?;
        match reconcile::reconcile(
            run,
            &mut cycle_budget,
            &mut local_reads,
            recheck_only,
            session,
            captured_bearer,
        )
        .await
        {
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
            Err(error) if reconcile::root_access_was_removed(&error) => {
                reconcile::finish_revoked_during_cycle(run, &pair)?;
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
    let final_state = run.finalize_all_roots_state(&selected_pair_id)?;
    let result = terminal.finish(&final_state);
    run.finish_persisted_state(final_state, |state| runtime.store.save(state))?;
    result
}

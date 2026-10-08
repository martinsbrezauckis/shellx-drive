//! Exact execution of one already-confirmed review decision.

#[path = "review_execution/authority.rs"]
mod authority;
#[path = "review_execution/mutations.rs"]
mod mutations;
#[path = "review_execution/retained.rs"]
mod retained;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ReviewExecution {
    Recheck,
    RetainedRootMoved { recovery: PathBuf },
}

pub(super) async fn execute_review_decision(
    state: &DesktopState,
    item: &ReviewItem,
    decision: ReviewDecision,
    session: Option<&SessionIdentity>,
    captured_bearer: Option<&str>,
    cycle_budget: &mut SyncCycleBudget,
) -> CoreResult<ReviewExecution> {
    let pair = state.pair.clone().ok_or(DesktopError::NeedsSetup)?;
    if decision == ReviewDecision::RemoveRetainedRoot {
        // The ordinary guard pins the root against deletion, which is correct
        // for every normal review but intentionally incompatible with moving
        // the complete retained root. Validate it first, then let the native
        // recovery move pin the parent and source object itself.
        {
            let _pair_root_guard = guard_configured_pair_roots(state, &pair.local_root)?;
        }
        let recovery = retained::move_retained_root_to_recovery(&pair)?;
        return Ok(ReviewExecution::RetainedRootMoved { recovery });
    }
    let _pair_root_guard = guard_configured_pair_roots(state, &pair.local_root)?;
    let baseline = baseline_for_review(state, item)?;
    let session = session.ok_or(DesktopError::NeedsReconnect)?;
    let captured_bearer = captured_bearer.ok_or(DesktopError::NeedsReconnect)?;
    let (client, token, remote) = authority::current_scoped_review(
        state,
        &pair,
        decision,
        session,
        captured_bearer,
        cycle_budget,
    )
    .await?;
    cycle_budget.admit(&remote, &[])?;
    mutations::execute(
        mutations::Inputs {
            client: &client,
            token: &token,
            pair: &pair,
            state,
            item,
            baseline,
            remote: &remote,
            cycle_budget,
        },
        decision,
    )
    .await?;
    Ok(ReviewExecution::Recheck)
}

pub(super) fn restore_retained_root_after_state_failure(
    pair: &SyncPair,
    recovery: &Path,
) -> CoreResult<()> {
    retained::restore_retained_root_after_state_failure(pair, recovery)
}

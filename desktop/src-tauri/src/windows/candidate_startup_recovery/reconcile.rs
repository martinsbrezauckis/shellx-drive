//! Exact staged-slot reconciliation before any desktop poller is started.

use super::super::*;
use super::recovery_error;

#[path = "reconcile/actions.rs"]
mod actions;
use actions::{
    complete_active_publication, promote_candidate, recover_unstaged_candidate,
    retire_unpromoted_candidate, slot_matches_record,
};

pub(super) struct StagedCandidate {
    slot: ServiceCredentialKey,
    bearer_token: String,
}

pub(super) async fn recover_staged_candidates(
    runtime: &Runtime,
    state: &mut DesktopState,
) -> CoreResult<()> {
    if let Some(record) = candidate_recovery_locator(state) {
        runtime.remember_candidate_recovery_record(record);
    }
    // Expiry ends remote authority, but the exact locator still owns a local
    // staged slot. Retain it until exact deletion/readback is confirmed.
    let mut candidates = staged_candidates(runtime, state)?;
    let unrecorded_candidate = state.pending_candidate_session.clone().filter(|record| {
        !candidates
            .iter()
            .any(|candidate| slot_matches_record(&candidate.slot, record))
    });
    if let Some(record) = unrecorded_candidate {
        // A confirmed failed staged write can leave the authoritative locator
        // without a slot. Resolve it before a stale canonical-matching slot
        // can see that locator and fail closed indefinitely.
        recover_unstaged_candidate(runtime, state, &record).await?;
    }
    candidates.sort_by(|left, right| {
        compare_staged_candidate_recovery_order(
            state,
            (
                &left.slot.identity.server_url,
                &left.slot.identity.email,
                &left.slot.session_id,
            ),
            (
                &right.slot.identity.server_url,
                &right.slot.identity.email,
                &right.slot.session_id,
            ),
        )
    });
    for candidate in candidates {
        if !runtime.owns_session_identity(&candidate.slot.identity) {
            // A duplicate sign-in can retain only its newly issued staged
            // session. Its canonical identity belongs to another runtime.
            retire_unpromoted_candidate(runtime, state, &candidate).await?;
            continue;
        }
        match staged_candidate_recovery_action(
            state,
            &candidate.slot.identity.server_url,
            &candidate.slot.identity.email,
            &candidate.slot.session_id,
            canonical_candidate_state(runtime, &candidate),
        ) {
            StagedCandidateRecoveryAction::Promote => {
                promote_candidate(runtime, state, &candidate)?
            }
            StagedCandidateRecoveryAction::CompleteActivePublication => {
                complete_active_publication(runtime, &candidate)?
            }
            StagedCandidateRecoveryAction::Retire => {
                retire_unpromoted_candidate(runtime, state, &candidate).await?
            }
            StagedCandidateRecoveryAction::Retain => return Err(recovery_error()),
        }
    }
    Ok(())
}

fn staged_candidates(runtime: &Runtime, state: &DesktopState) -> CoreResult<Vec<StagedCandidate>> {
    let mut candidates = Vec::new();
    for slot in pending_session_retirement::owned_pending_slots(state)? {
        if let Some(bearer_token) = PendingWindowsCredentialStore
            .get(&slot.account_key)
            .map_err(|_| recovery_error())?
        {
            runtime.remember_candidate_recovery_identity(&slot.identity);
            candidates.push(StagedCandidate { slot, bearer_token });
        }
    }
    Ok(candidates)
}

fn canonical_candidate_state(
    runtime: &Runtime,
    candidate: &StagedCandidate,
) -> ExactCredentialRead {
    let account_key = candidate.slot.identity.credential_key();
    classify_exact_credential_readback(
        runtime.platform.credentials().get(&account_key),
        &candidate.bearer_token,
    )
}

//! Exact staged-slot recovery with durable ownership until deletion.

use super::super::super::{
    remote_revocations::remove_staged_slot,
    session_credentials::complete_staged_candidate_promotion,
};
use super::super::recovery_error;
use super::*;

pub(super) fn slot_matches_record(
    slot: &ServiceCredentialKey,
    record: &RemoteSessionRecord,
) -> bool {
    record.identity_matches(&slot.identity.server_url, &slot.identity.email)
        && record.session_id == slot.session_id
}

fn state_record_for_slot(
    state: &DesktopState,
    slot: &ServiceCredentialKey,
) -> Option<RemoteSessionRecord> {
    state
        .pending_candidate_session
        .iter()
        .chain(state.active_remote_session.iter())
        .chain(state.pending_remote_revocations.iter())
        .find(|record| slot_matches_record(slot, record))
        .cloned()
}

pub(super) fn complete_active_publication(
    runtime: &Runtime,
    candidate: &StagedCandidate,
) -> CoreResult<()> {
    // The active locator was saved before canonical publication. Re-write and
    // probe the exact canonical destination instead of logging the candidate
    // out merely because an old canonical bearer is still present.
    complete_staged_candidate_promotion(runtime, &candidate.slot.identity, &candidate.bearer_token)
        .map_err(|_| recovery_error())?;
    remove_staged_slot(&candidate.slot).map_err(|_| recovery_error())
}

pub(super) fn promote_candidate(
    runtime: &Runtime,
    state: &mut DesktopState,
    candidate: &StagedCandidate,
) -> CoreResult<()> {
    let record = state_record_for_slot(state, &candidate.slot).or_else(|| {
        RemoteSessionRecord::from_local_bearer(
            &candidate.slot.identity.server_url,
            &candidate.slot.identity.email,
            &candidate.bearer_token,
        )
    });
    let Some(record) = record else {
        // A slot ID is not sufficient to reconstruct opaque-session metadata.
        return Err(recovery_error());
    };
    let mut persisted = state.clone();
    persisted.publish_active_remote_session(record);
    runtime.store.save(&persisted)?;
    *state = persisted;
    remove_staged_slot(&candidate.slot).map_err(|_| recovery_error())
}

pub(super) async fn retire_unpromoted_candidate(
    runtime: &Runtime,
    state: &mut DesktopState,
    candidate: &StagedCandidate,
) -> CoreResult<()> {
    let client =
        DriveHttpClient::new(&candidate.slot.identity.server_url).map_err(|_| recovery_error())?;
    client
        .logout(&candidate.bearer_token)
        .await
        .map_err(|_| recovery_error())?;
    // Confirm exact local deletion before dropping its durable locator. A
    // provider failure retains ownership for retry; a save failure retains a
    // locator whose already-absent slot can be safely rechecked.
    remove_staged_slot(&candidate.slot).map_err(|_| recovery_error())?;
    if let Some(record) = state_record_for_slot(state, &candidate.slot) {
        let persisted = state_after_confirmed_remote_retirement(state, &record);
        runtime.store.save(&persisted)?;
        *state = persisted;
    }
    Ok(())
}

pub(super) async fn recover_unstaged_candidate(
    runtime: &Runtime,
    state: &mut DesktopState,
    record: &RemoteSessionRecord,
) -> CoreResult<()> {
    let identity = SessionIdentity::new(&record.server_url, &record.account_email);
    if !runtime.owns_session_identity(&identity) {
        return Err(recovery_error());
    }
    let bearer_token = runtime
        .platform
        .credentials()
        .get(&identity.credential_key())
        .map_err(|_| recovery_error())?
        .ok_or_else(recovery_error)?;
    let canonical_record = RemoteSessionRecord::from_local_bearer(
        &record.server_url,
        &record.account_email,
        &bearer_token,
    )
    .ok_or_else(recovery_error)?;
    let mut persisted = state.clone();
    if canonical_record.same_remote_session(record) {
        persisted.publish_active_remote_session(record.clone());
    } else {
        let client = DriveHttpClient::new(&record.server_url).map_err(|_| recovery_error())?;
        client
            .revoke_session(&bearer_token, &record.session_id)
            .await
            .map_err(|_| recovery_error())?;
        persisted = state_after_confirmed_remote_retirement(state, record);
    }
    runtime.store.save(&persisted)?;
    *state = persisted;
    Ok(())
}

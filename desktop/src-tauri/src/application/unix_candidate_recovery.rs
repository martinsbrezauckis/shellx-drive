//! Exact staged-slot recovery shared by the Unix credential adapters.

use std::future::Future;

use shellx_drive_desktop_core::{
    classify_exact_credential_readback, classify_exact_credential_removal,
    classify_exact_credential_write, compare_staged_candidate_recovery_order,
    staged_candidate_recovery_action, state_after_confirmed_remote_retirement, CredentialStore,
    DesktopError, DesktopState, ExactCredentialRemoval, ExactCredentialWrite, RemoteSessionRecord,
    Result as CoreResult, StagedCandidateRecoveryAction,
};

use crate::session_identity::{ServiceCredentialKey, SessionIdentity};

pub(super) struct RecoveryStores<'a> {
    pub canonical: &'a dyn CredentialStore,
    pub pending: &'a dyn CredentialStore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RemoteRecoveryAction {
    RetireCandidate,
    RetirePriorCanonical,
}

/// Publish convergence only after the adapter verified canonical publication
/// and removed every staged slot. A failed save retains the recovery error.
pub(super) fn persist_converged_candidate_state(
    state: &mut DesktopState,
    pending_keys: Vec<String>,
    save: impl FnOnce(&DesktopState) -> CoreResult<()>,
) -> CoreResult<()> {
    if state.pending_candidate_session.is_some()
        || !pending_keys.is_empty()
        || state.has_pending_disconnect_cleanup()
    {
        return Err(recovery_error());
    }
    let mut persisted = state.clone();
    persisted.clear_candidate_recovery_error();
    save(&persisted)?;
    *state = persisted;
    Ok(())
}

pub(super) fn ordered_slots(
    state: &DesktopState,
    keys: Vec<String>,
) -> CoreResult<Vec<ServiceCredentialKey>> {
    let mut slots = keys
        .into_iter()
        .map(|key| SessionIdentity::parse_pending_service_key(&key).ok_or_else(recovery_error))
        .collect::<CoreResult<Vec<_>>>()?;
    slots.sort_by(|left, right| {
        compare_staged_candidate_recovery_order(
            state,
            (
                &left.identity.server_url,
                &left.identity.email,
                &left.session_id,
            ),
            (
                &right.identity.server_url,
                &right.identity.email,
                &right.session_id,
            ),
        )
    });
    Ok(slots)
}

/// Provider uncertainty retains both the locator and staged credential. Only
/// canonical equality or an already-durable active locator permits publication.
pub(super) async fn recover_slot<Save, Remote, RemoteFuture, Cleanup>(
    state: &mut DesktopState,
    slot: &ServiceCredentialKey,
    bearer: &str,
    stores: RecoveryStores<'_>,
    save: Save,
    remote: Remote,
    cleanup_canonical: Cleanup,
) -> CoreResult<()>
where
    Save: FnOnce(&DesktopState) -> CoreResult<()>,
    Remote: FnOnce(RemoteRecoveryAction) -> RemoteFuture,
    RemoteFuture: Future<Output = CoreResult<()>>,
    Cleanup: FnOnce() -> CoreResult<()>,
{
    let canonical_key = slot.identity.credential_key();
    let action = staged_candidate_recovery_action(
        state,
        &slot.identity.server_url,
        &slot.identity.email,
        &slot.session_id,
        classify_exact_credential_readback(stores.canonical.get(&canonical_key), bearer),
    );
    match action {
        StagedCandidateRecoveryAction::Retain => return Err(recovery_error()),
        StagedCandidateRecoveryAction::Retire => {
            remote(RemoteRecoveryAction::RetireCandidate).await?;
            if let Some(record) = matching_record(state, slot) {
                // Confirm retirement and save locator removal before deleting
                // the only staged bearer. A failed save retains admission.
                let persisted = state_after_confirmed_remote_retirement(state, &record);
                save(&persisted)?;
                *state = persisted;
            }
        }
        StagedCandidateRecoveryAction::Promote => {
            let record = matching_record(state, slot)
                .or_else(|| {
                    RemoteSessionRecord::from_local_bearer(
                        &slot.identity.server_url,
                        &slot.identity.email,
                        bearer,
                    )
                })
                .filter(|record| record.session_id == slot.session_id)
                .ok_or_else(recovery_error)?;
            remote(RemoteRecoveryAction::RetirePriorCanonical).await?;
            let mut persisted = state.clone();
            persisted.publish_active_remote_session(record);
            save(&persisted)?;
            *state = persisted;
            cleanup_canonical()?;
        }
        StagedCandidateRecoveryAction::CompleteActivePublication => {
            // The exact active locator was saved before canonical write.
            // Preserve any newer pending locator while completing that write.
            remote(RemoteRecoveryAction::RetirePriorCanonical).await?;
            match classify_exact_credential_write(
                stores.canonical.set(&canonical_key, bearer),
                stores.canonical.get(&canonical_key),
                bearer,
            ) {
                ExactCredentialWrite::Written => {}
                ExactCredentialWrite::NotWritten | ExactCredentialWrite::Unknown => {
                    return Err(recovery_error());
                }
            }
            cleanup_canonical()?;
        }
    }
    match classify_exact_credential_removal(
        stores.pending.delete(&slot.account_key),
        stores.pending.get(&slot.account_key),
    ) {
        ExactCredentialRemoval::Removed => Ok(()),
        ExactCredentialRemoval::Retained | ExactCredentialRemoval::Unknown => Err(recovery_error()),
    }
}

fn matching_record(
    state: &DesktopState,
    slot: &ServiceCredentialKey,
) -> Option<RemoteSessionRecord> {
    state
        .pending_candidate_session
        .iter()
        .chain(state.active_remote_session.iter())
        .chain(state.pending_remote_revocations.iter())
        .find(|record| {
            record.session_id == slot.session_id
                && record.identity_matches(&slot.identity.server_url, &slot.identity.email)
        })
        .cloned()
}

fn recovery_error() -> DesktopError {
    DesktopError::Credential(
        "Drive credential recovery needs retry; credentials were kept for retry".to_string(),
    )
}

#[cfg(test)]
mod publication_tests;
#[cfg(test)]
mod tests;

//! Exact retirement through a fresh same-identity sign-in.

use std::{collections::BTreeSet, future::Future};

use shellx_drive_desktop_core::{
    CredentialStore, DesktopState, RemoteSessionRecord, Result as CoreResult,
};

use crate::session_identity::SessionIdentity;

use super::{recovery_error, remove_retired_slot};

/// A failed final save can retain a locator after its bearer was deleted.
/// Recover from the durable session identity, never from provider enumeration
/// or a matching account alone. The fresh bearer authorizes exact retirement.
pub(in crate::application) async fn retire_prior_candidate_sessions<Save, Remote, RemoteFuture>(
    state: &mut DesktopState,
    pending: &dyn CredentialStore,
    identity: &SessionIdentity,
    current: &RemoteSessionRecord,
    save: Save,
    mut remote: Remote,
) -> CoreResult<()>
where
    Save: Fn(&DesktopState) -> CoreResult<()>,
    Remote: FnMut(RemoteSessionRecord) -> RemoteFuture,
    RemoteFuture: Future<Output = CoreResult<()>>,
{
    let mut seen = BTreeSet::new();
    let records = state
        .pending_candidate_session
        .iter()
        .chain(state.active_remote_session.iter())
        .chain(state.pending_remote_revocations.iter())
        .filter(|record| {
            record.identity_matches(&identity.server_url, &identity.email)
                && !record.same_remote_session(current)
                && seen.insert(record.session_id.clone())
        })
        .cloned()
        .collect::<Vec<_>>();
    for record in records {
        let slot = identity
            .pending_service_key(&record.session_id)
            .ok_or_else(recovery_error)?;
        remote(record).await?;
        remove_retired_slot(state, &slot, pending, &save)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

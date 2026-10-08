use super::*;
use shellx_drive_desktop_core::{
    classify_exact_credential_removal, classify_exact_credential_write, DesktopState,
    ExactCredentialRemoval, ExactCredentialWrite,
};

pub(super) async fn retire_prior_sessions(
    runtime: &Runtime,
    candidate: &SessionIdentity,
    candidate_bearer: &str,
) -> CoreResult<()> {
    if !runtime.owns_session_identity(candidate) {
        return Err(candidate_error());
    }
    if let Some(bearer) = runtime
        .platform
        .credentials()
        .get(&candidate.credential_key())?
    {
        if bearer != candidate_bearer {
            DriveHttpClient::new(&candidate.server_url)?
                .logout(&bearer)
                .await
                .map_err(|_| candidate_error())?;
        }
    }
    Ok(())
}

pub(super) fn pending_locator_keys(state: &DesktopState) -> std::collections::BTreeSet<String> {
    state.pending_candidate_session.iter().chain(state.active_remote_session.iter())
        .chain(state.pending_remote_revocations.iter())
        .filter_map(|record| SessionIdentity::new(&record.server_url, &record.account_email)
            .pending_service_key(&record.session_id).map(|slot| slot.account_key))
        .chain(state.pending_disconnect_cleanup().into_iter().flat_map(|cleanup| cleanup.credential_slots.iter())
            .filter(|slot| slot.namespace == shellx_drive_desktop_core::DisconnectCredentialNamespace::PendingCandidate)
            .map(|slot| slot.account_key.clone()))
        .collect()
}

pub(super) fn owned_pending_keys(state: &DesktopState) -> CoreResult<Vec<String>> {
    let owned = pending_locator_keys(state);
    if owned.is_empty() {
        return Ok(Vec::new());
    }
    Ok(PendingMacOsCredentialStore::service_account_keys()?
        .into_iter()
        .filter(|key| owned.contains(key))
        .collect())
}

pub(super) fn write_exact(store: &dyn CredentialStore, key: &str, bearer: &str) -> CoreResult<()> {
    match classify_exact_credential_write(store.set(key, bearer), store.get(key), bearer) {
        ExactCredentialWrite::Written => Ok(()),
        ExactCredentialWrite::NotWritten | ExactCredentialWrite::Unknown => Err(candidate_error()),
    }
}

pub(super) fn remove_exact(store: &dyn CredentialStore, key: &str) -> CoreResult<()> {
    match classify_exact_credential_removal(store.delete(key), store.get(key)) {
        ExactCredentialRemoval::Removed => Ok(()),
        ExactCredentialRemoval::Retained | ExactCredentialRemoval::Unknown => {
            Err(candidate_error())
        }
    }
}

pub(super) fn begin_login_publication(
    stopped: &mut DisconnectRequest,
) -> CoreResult<shellx_drive_desktop_core::LifecycleOperation> {
    stopped.try_begin()?.ok_or_else(|| {
        DesktopError::InvalidState("Drive synchronization has not stopped for sign-in".to_string())
    })
}

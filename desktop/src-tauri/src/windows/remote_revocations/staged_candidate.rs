//! Exact pending-candidate Credential Manager operations.

use super::*;

fn staging_error() -> DesktopError {
    DesktopError::Credential(
        "pending Drive credential could not be staged; credentials were kept for retry".to_string(),
    )
}

fn cleanup_error() -> DesktopError {
    DesktopError::Credential("pending Drive credential cleanup failed".to_string())
}

fn candidate_slot(record: &RemoteSessionRecord) -> CoreResult<ServiceCredentialKey> {
    SessionIdentity::new(&record.server_url, &record.account_email)
        .pending_service_key(&record.session_id)
        .ok_or_else(staging_error)
}

/// Stage a bearer in the dedicated candidate namespace. The provider result
/// alone is not authoritative: an error can arrive after it committed, so the
/// exact destination is always probed before deciding whether staging worked.
pub(in crate::application) fn stage_pending_candidate(
    client: &DriveHttpClient,
    bearer_token: &str,
    record: &RemoteSessionRecord,
) -> CoreResult<()> {
    let identity = SessionIdentity::new(client.normalized_url(), &record.account_email);
    let slot = identity
        .pending_service_key(&record.session_id)
        .ok_or_else(staging_error)?;
    let write = PendingWindowsCredentialStore.set(&slot.account_key, bearer_token);
    let readback = PendingWindowsCredentialStore.get(&slot.account_key);
    match classify_exact_credential_write(write, readback, bearer_token) {
        ExactCredentialWrite::Written => Ok(()),
        ExactCredentialWrite::NotWritten | ExactCredentialWrite::Unknown => Err(staging_error()),
    }
}

/// The canonical key is already known to contain the candidate. Delete only
/// this exact staged slot and verify removal even if Credential Manager first
/// returned an error after performing the deletion.
pub(in crate::application) fn remove_staged_candidate(
    record: &RemoteSessionRecord,
) -> CoreResult<()> {
    remove_staged_slot(&candidate_slot(record)?)
}

pub(in crate::application) fn remove_staged_slot(slot: &ServiceCredentialKey) -> CoreResult<()> {
    let deletion = PendingWindowsCredentialStore.delete(&slot.account_key);
    let readback = PendingWindowsCredentialStore.get(&slot.account_key);
    match classify_exact_credential_removal(deletion, readback) {
        ExactCredentialRemoval::Removed => Ok(()),
        ExactCredentialRemoval::Retained | ExactCredentialRemoval::Unknown => Err(cleanup_error()),
    }
}

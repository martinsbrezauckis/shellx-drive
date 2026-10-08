//! Same-identity retirement of older macOS staged candidates.

use chrono::Utc;
use shellx_drive_desktop_core::{
    classify_exact_credential_removal, CredentialStore, DesktopError, DriveHttpClient,
    ExactCredentialRemoval, PendingMacOsCredentialStore, RemoteSessionRecord, Result as CoreResult,
};

use crate::session_identity::SessionIdentity;

/// A same-identity retry may clear an older retained candidate using its fresh
/// bearer. A different identity must never replace or consume that candidate.
pub(super) async fn recover_prior_candidates(
    state: &mut shellx_drive_desktop_core::DesktopState,
    client: &DriveHttpClient,
    fresh_bearer: &str,
    identity: &SessionIdentity,
    current: &RemoteSessionRecord,
) -> CoreResult<()> {
    let current_key = identity
        .pending_service_key(&current.session_id)
        .ok_or_else(recovery_error)?
        .account_key;
    let pending = PendingMacOsCredentialStore;
    for key in PendingMacOsCredentialStore::service_account_keys()? {
        let slot = SessionIdentity::parse_pending_service_key(&key).ok_or_else(recovery_error)?;
        if slot.account_key == current_key {
            continue;
        }
        if slot.identity.credential_key() != identity.credential_key() {
            return Err(recovery_error());
        }
        client
            .revoke_session(fresh_bearer, &slot.session_id)
            .await?;
        if !matches!(
            classify_exact_credential_removal(
                pending.delete(&slot.account_key),
                pending.get(&slot.account_key)
            ),
            ExactCredentialRemoval::Removed
        ) {
            return Err(recovery_error());
        }
    }

    for record in state.pending_remote_revocations_for_identity(
        &identity.server_url,
        &identity.email,
        Utc::now(),
    ) {
        client
            .revoke_session(fresh_bearer, &record.session_id)
            .await?;
        state.remove_remote_session_record(&record);
    }
    Ok(())
}

fn recovery_error() -> DesktopError {
    DesktopError::Credential(
        "credential recovery permits sign-in only for the retained server and account".to_string(),
    )
}

//! Same-identity retirement of stale Linux staged candidates.

use chrono::Utc;
use shellx_drive_desktop_core::{
    classify_exact_credential_removal, CredentialStore, DesktopError, DriveHttpClient,
    ExactCredentialRemoval, PendingLinuxCredentialStore, RemoteSessionRecord, Result as CoreResult,
};

use crate::session_identity::SessionIdentity;

/// A staged bearer belongs to an exact server/account/session tuple. A fresh
/// same-identity sign-in may revoke it; another identity is never permitted to
/// guess at or overwrite it.
pub(super) async fn recover_prior_candidates(
    state: &mut shellx_drive_desktop_core::DesktopState,
    pending: &PendingLinuxCredentialStore,
    client: &DriveHttpClient,
    fresh_bearer: &str,
    identity: &SessionIdentity,
    current: &RemoteSessionRecord,
) -> CoreResult<()> {
    for key in PendingLinuxCredentialStore::service_account_keys()? {
        let slot = SessionIdentity::parse_pending_service_key(&key).ok_or_else(|| {
            DesktopError::Credential(
                "a staged Drive credential has an invalid recovery identity".to_string(),
            )
        })?;
        if slot.account_key
            == identity
                .pending_service_key(&current.session_id)
                .ok_or_else(|| {
                    DesktopError::Credential(
                        "Drive returned an invalid session identifier".to_string(),
                    )
                })?
                .account_key
        {
            continue;
        }
        if slot.identity.credential_key() != identity.credential_key() {
            return Err(DesktopError::Credential(
                "credential recovery permits sign-in only for the retained server and account"
                    .to_string(),
            ));
        }
        client
            .revoke_session(fresh_bearer, &slot.session_id)
            .await?;
        let removed = pending.delete(&slot.account_key);
        let readback = pending.get(&slot.account_key);
        if !matches!(
            classify_exact_credential_removal(removed, readback),
            ExactCredentialRemoval::Removed
        ) {
            return Err(DesktopError::Credential(
                "staged Drive credential cleanup was not confirmed".to_string(),
            ));
        }
    }

    let retained = state.pending_remote_revocations_for_identity(
        &identity.server_url,
        &identity.email,
        Utc::now(),
    );
    for record in retained {
        client
            .revoke_session(fresh_bearer, &record.session_id)
            .await?;
        state.remove_remote_session_record(&record);
    }
    Ok(())
}

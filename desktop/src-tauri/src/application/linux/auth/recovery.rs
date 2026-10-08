//! Same-identity retirement of stale Linux staged candidates.

use shellx_drive_desktop_core::{
    DriveHttpClient, PendingLinuxCredentialStore, RemoteSessionRecord, Result as CoreResult,
};

use crate::{application::Runtime, session_identity::SessionIdentity};

/// A staged bearer belongs to an exact server/account/session tuple. A fresh
/// same-identity sign-in may revoke it; another identity is never permitted to
/// guess at or overwrite it.
pub(super) async fn recover_prior_candidates(
    runtime: &Runtime,
    state: &mut shellx_drive_desktop_core::DesktopState,
    pending: &PendingLinuxCredentialStore,
    client: &DriveHttpClient,
    fresh_bearer: &str,
    identity: &SessionIdentity,
    current: &RemoteSessionRecord,
) -> CoreResult<()> {
    crate::application::unix_candidate_recovery::retire_prior_candidate_sessions(
        state,
        pending,
        identity,
        current,
        |persisted| runtime.store.save(persisted),
        |record| async move {
            client
                .revoke_session(fresh_bearer, &record.session_id)
                .await
                .map(|_| ())
        },
    )
    .await
}

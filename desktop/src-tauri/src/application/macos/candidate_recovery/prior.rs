//! Exact same-account retirement before macOS canonical publication.

use crate::{application::Runtime, session_identity::SessionIdentity};
use shellx_drive_desktop_core::{
    DesktopState, DriveHttpClient, PendingMacOsCredentialStore, RemoteSessionRecord,
    Result as CoreResult,
};

pub(super) async fn recover_prior_candidates(
    runtime: &Runtime,
    state: &mut DesktopState,
    client: &DriveHttpClient,
    fresh_bearer: &str,
    identity: &SessionIdentity,
    current: &RemoteSessionRecord,
) -> CoreResult<()> {
    crate::application::unix_candidate_recovery::retire_prior_candidate_sessions(
        state,
        &PendingMacOsCredentialStore,
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

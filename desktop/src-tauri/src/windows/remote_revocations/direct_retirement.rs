//! Direct logout keeps exact staged ownership until local deletion succeeds.

use super::*;

pub(super) async fn retire_bearer(
    state: &mut DesktopState,
    credential: &StoredSessionCredential,
    record: Option<&RemoteSessionRecord>,
) -> CoreResult<()> {
    let outcome = match DriveHttpClient::new(&credential.identity.server_url) {
        Ok(client) => client.logout(&credential.bearer_token).await,
        Err(error) => Err(error),
    };
    let confirmed = confirm_direct_retirement(record.cloned(), outcome)?;
    finish_direct_retirement(state, credential, confirmed, remove_staged_candidate)
}

fn finish_direct_retirement(
    state: &mut DesktopState,
    credential: &StoredSessionCredential,
    confirmed: Option<RemoteSessionRecord>,
    remove_pending: impl FnOnce(&RemoteSessionRecord) -> CoreResult<()>,
) -> CoreResult<()> {
    if let Some(record) = confirmed {
        // A typed foreign legacy locator owns only this exact pending slot.
        // Canonical credentials have no staged session ID and remain scoped
        // to their catalog owner. This path is authentication publication;
        // Disconnect retains its separate durable cleanup-journal ordering.
        if credential.session_id.as_deref() == Some(record.session_id.as_str()) {
            remove_pending(&record)?;
        }
        state.remove_remote_session_record(&record);
    }
    Ok(())
}

#[cfg(test)]
#[path = "direct_retirement/tests.rs"]
mod tests;

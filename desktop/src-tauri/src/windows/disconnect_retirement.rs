//! Fail-closed credential retirement for the normal Disconnect command.

use super::{pending_session_retirement::*, *};

/// Disconnect is offboarding, not best-effort cleanup. It retains the pair
/// and every local Drive credential unless each exact bearer is remotely
/// revoked or already invalid.
pub(super) async fn retire_stored_credentials_for_disconnect(
    runtime: &Runtime,
    state: &mut DesktopState,
    fallback: Option<&SessionIdentity>,
) -> CoreResult<()> {
    let stored = stored_session_credentials(runtime, state, fallback)?;
    if stored.is_empty() && fallback.is_some() {
        return Err(DesktopError::Credential(
            "the saved Drive session has no retrievable credential; pair was kept for retry"
                .to_string(),
        ));
    }

    let direct_retirements = direct_retirement_records(state, &stored);
    let direct_records = direct_retirements
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    // A no-slot recovery candidate is still a live remote session. Move its
    // durable locator into the ordinary retirement queue before declaring the
    // remote phase complete. A staged candidate with a matching bearer is in
    // `direct_records` and therefore remains assigned to its exact logout.
    // Retire every older session while its matching bearer remains valid. The
    // direct session tied to each local bearer is instead confirmed by logout,
    // whose AlreadyInvalid outcome makes a save-failure retry safe.
    retire_pending_remote_sessions(state, &stored, None, None, &direct_records, true).await?;
    runtime.store.save(state)?;

    for (credential, direct_retirement) in stored.iter().zip(&direct_retirements) {
        let mut logout = Some(
            match DriveHttpClient::new(&credential.identity.server_url) {
                Ok(client) => client.logout(&credential.bearer_token).await,
                Err(error) => Err(error),
            },
        );
        confirm_remote_retirement(std::iter::once(credential), |_| {
            logout
                .take()
                .expect("one remote retirement result per stored credential")
        })?;
        if let Some(record) = direct_retirement {
            state.remove_remote_session_record(record);
        }
        // Persist every confirmed direct logout before attempting the next
        // bearer or deleting local credentials. A failed save leaves the
        // bearer for a retry, and logout treats it as AlreadyInvalid.
        runtime.store.save(state)?;
    }

    state.active_remote_session = None;
    // The caller first persists a non-secret exact local-cleanup journal.
    // Credential Manager and pair-marker removal happen only after the
    // disconnected state itself is durable in `disconnect_cleanup`.
    runtime.store.save(state)
}

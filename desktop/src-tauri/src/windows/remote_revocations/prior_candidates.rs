//! Preserve each prior slot until exact retirement and local deletion finish.

use super::*;

pub(super) async fn retire_prior_candidate_sessions(
    runtime: &Runtime,
    state: &mut DesktopState,
    identity: &SessionIdentity,
    current: &RemoteSessionRecord,
    client: &DriveHttpClient,
    bearer_token: &str,
) -> CoreResult<()> {
    let records = state
        .pending_candidate_session
        .iter()
        .chain(state.active_remote_session.iter())
        .chain(state.pending_remote_revocations.iter())
        .filter(|record| {
            record.identity_matches(&identity.server_url, &identity.email)
                && !record.same_remote_session(current)
        })
        .map(|record| (record.session_id.clone(), record.clone()))
        .collect::<BTreeMap<_, _>>();
    for record in records.into_values() {
        client
            .revoke_session(bearer_token, &record.session_id)
            .await?;
        remove_staged_candidate(&record)?;
        let persisted = state_after_confirmed_remote_retirement(state, &record);
        runtime.store.save(&persisted)?;
        *state = persisted;
    }
    Ok(())
}

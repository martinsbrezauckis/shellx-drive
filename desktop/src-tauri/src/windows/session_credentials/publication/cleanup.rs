use super::super::super::{
    remote_revocations::{retire_failed_candidate, retire_unpublished_session},
    *,
};
use super::{canonical_candidate_state, CanonicalCandidateState};

pub(super) async fn admit_candidate_publication(
    runtime: &Runtime,
    stopped: &mut DisconnectRequest,
    client: &DriveHttpClient,
    bearer_token: &str,
    candidate: &RemoteSessionRecord,
    generation: u64,
) -> CoreResult<()> {
    if runtime.auth_offboarding.may_publish(generation) {
        return Ok(());
    }
    retire_unpublished_session(
        runtime,
        stopped,
        client,
        bearer_token,
        &candidate.account_email,
        &candidate.session_id,
        candidate.expires_at,
    )
    .await?;
    Err(DesktopError::InvalidState(
        "Sign-in was canceled by Disconnect before credentials were published.".to_string(),
    ))
}

pub(super) async fn preserve_unpublished_candidate(
    runtime: &Runtime,
    state: &mut DesktopState,
    client: &DriveHttpClient,
    bearer_token: &str,
    record: &RemoteSessionRecord,
) -> CoreResult<()> {
    // Never revoke a candidate until an exact canonical read proves that the
    // canonical destination does not contain it. A provider can fail after a
    // canonical write, and revoking in that ambiguity would otherwise destroy
    // the only authorizer for the retained pair.
    match canonical_candidate_state(runtime, record, bearer_token) {
        CanonicalCandidateState::NotPublished => {
            retire_failed_candidate(runtime, state, client, bearer_token, record).await
        }
        CanonicalCandidateState::Published | CanonicalCandidateState::Unknown => {
            Err(DesktopError::Credential(
                "Drive credential publication needs recovery; credentials were kept for retry"
                    .to_string(),
            ))
        }
    }
}

use super::super::{
    remote_revocations::{
        remove_staged_candidate, retire_stored_credentials, retire_unpublished_session,
        stage_candidate_for_publication,
    },
    *,
};

#[path = "publication/canonical.rs"]
mod canonical;
#[path = "publication/cleanup.rs"]
mod cleanup;

#[cfg(test)]
#[path = "publication/tests.rs"]
mod tests;

pub(in crate::application) use canonical::complete_staged_candidate_promotion;
use canonical::{canonical_candidate_state, publish_canonical_candidate, CanonicalCandidateState};
use cleanup::{admit_candidate_publication, preserve_unpublished_candidate};

pub(in crate::application) async fn publish_authenticated_session(
    runtime: &Runtime,
    stopped: &mut DisconnectRequest,
    client: &DriveHttpClient,
    bearer_token: &str,
    account_email: &str,
    session_id: &str,
    expires_at: chrono::DateTime<Utc>,
    generation: u64,
) -> CoreResult<()> {
    let next = SessionIdentity::new(client.normalized_url(), account_email);
    let next_key = next.credential_key();
    let candidate = RemoteSessionRecord::new(
        client.normalized_url(),
        account_email,
        session_id,
        expires_at,
    )?;
    admit_candidate_publication(
        runtime,
        stopped,
        client,
        bearer_token,
        &candidate,
        generation,
    )
    .await?;
    if let Err(error) =
        runtime.ensure_login_matches_retained_pair(client.normalized_url(), account_email)
    {
        retire_unpublished_session(
            runtime,
            stopped,
            client,
            bearer_token,
            account_email,
            session_id,
            expires_at,
        )
        .await?;
        return Err(error);
    }
    // Promote the same request retained before the session was issued. A new
    // sync or removal cannot win a lifecycle admission between HTTP and this
    // durable publication.
    let mut operation = match begin_login_publication(stopped) {
        Ok(operation) => operation,
        Err(error) => {
            retire_unpublished_session(
                runtime,
                stopped,
                client,
                bearer_token,
                account_email,
                session_id,
                expires_at,
            )
            .await?;
            return Err(error);
        }
    };
    let mut state = runtime.coordinator.snapshot();
    if let Err(error) =
        stage_candidate_for_publication(runtime, &mut state, client, bearer_token, &candidate)
    {
        operation.finish_state(state);
        return Err(error);
    }
    let previous = runtime
        .session
        .lock()
        .expect("session lock")
        .clone()
        .or_else(|| {
            state
                .pair
                .as_ref()
                .map(|pair| SessionIdentity::new(&pair.server_url, &pair.account_email))
        });
    if let Err(error) = retire_stored_credentials(
        runtime,
        &mut state,
        previous.as_ref(),
        Some((&next, client, bearer_token, &candidate)),
    )
    .await
    {
        let cleanup =
            preserve_unpublished_candidate(runtime, &mut state, client, bearer_token, &candidate)
                .await;
        operation.finish_state(state);
        if cleanup.is_ok() {
            runtime.refresh_candidate_recovery_pending();
        }
        return Err(error);
    }
    *runtime.session.lock().expect("session lock") = None;
    // Recheck immediately before the canonical write. If Disconnect latches
    // after this point it waits on the surrounding publication serializer and
    // then retires the resulting exact credential through its durable journal.
    if !runtime.auth_offboarding.may_publish(generation) {
        let cleanup =
            preserve_unpublished_candidate(runtime, &mut state, client, bearer_token, &candidate)
                .await;
        operation.finish_state(state);
        cleanup?;
        return Err(DesktopError::InvalidState(
            "Sign-in was canceled by Disconnect before credentials were published.".to_string(),
        ));
    }
    match publish_canonical_candidate(runtime, &next_key, bearer_token) {
        CanonicalCandidateState::Published => {}
        CanonicalCandidateState::NotPublished
            if state
                .active_remote_session
                .as_ref()
                .is_some_and(|active| active.same_remote_session(&candidate)) =>
        {
            // An active candidate is half-published: retry, never log it out.
            if let Err(error) = complete_staged_candidate_promotion(runtime, &next, bearer_token) {
                operation.finish_state(state);
                return Err(error);
            }
        }
        CanonicalCandidateState::NotPublished => {
            let cleanup = preserve_unpublished_candidate(
                runtime,
                &mut state,
                client,
                bearer_token,
                &candidate,
            )
            .await;
            operation.finish_state(state);
            if cleanup.is_ok() {
                runtime.refresh_candidate_recovery_pending();
            }
            return Err(DesktopError::Credential(
                "Drive credential publication was not confirmed".to_string(),
            ));
        }
        CanonicalCandidateState::Unknown => {
            operation.finish_state(state);
            return Err(DesktopError::Credential(
                "Drive credential publication needs recovery; credentials were kept for retry"
                    .to_string(),
            ));
        }
    }
    if let Err(error) = remove_staged_candidate(&candidate) {
        *runtime.session.lock().expect("session lock") = Some(next);
        operation.finish_state(state);
        return Err(error);
    }
    *runtime.session.lock().expect("session lock") = Some(next);
    operation.finish_state(state);
    runtime.refresh_candidate_recovery_pending();
    Ok(())
}

fn begin_login_publication(
    stopped: &mut DisconnectRequest,
) -> CoreResult<shellx_drive_desktop_core::LifecycleOperation> {
    stopped.try_begin()?.ok_or_else(|| {
        DesktopError::InvalidState("Drive synchronization has not stopped for sign-in".to_string())
    })
}

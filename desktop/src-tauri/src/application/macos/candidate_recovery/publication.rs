use super::*;
use chrono::Utc;

pub(in crate::application::macos) async fn publish_authenticated_session(
    runtime: &Runtime,
    manager: &ConnectionManager,
    stopped: &mut DisconnectRequest,
    client: &DriveHttpClient,
    bearer_token: &str,
    account_email: &str,
    session_id: &str,
    expires_at: chrono::DateTime<Utc>,
    generation: u64,
) -> CoreResult<()> {
    let identity = SessionIdentity::new(client.normalized_url(), account_email);
    let record = RemoteSessionRecord::new(
        client.normalized_url(),
        account_email,
        session_id,
        expires_at,
    )?;
    let slot = identity
        .pending_service_key(session_id)
        .ok_or_else(candidate_error)?;
    // Hold the terminal serializer while retiring an outdated response. This
    // is the same ordering as Windows: Disconnect waits on the serializer,
    // while a newer generation cannot republish this bearer or candidate.
    let _publication = runtime.auth_publication.lock().await;
    if !runtime.auth_offboarding.may_publish(generation) {
        retire_unpublished_response(
            runtime,
            stopped,
            client,
            bearer_token,
            &record,
            &slot.account_key,
        )
        .await?;
        refresh_pending(runtime);
        return Err(canceled_sign_in());
    }
    let admission = runtime
        .ensure_login_matches_retained_pair(client.normalized_url(), account_email)
        .and_then(|()| {
            let id = manager.id_for_runtime(runtime).ok_or_else(|| {
                DesktopError::InvalidState("Drive connection is no longer registered".to_string())
            })?;
            manager.reserve_identity(&id, client.normalized_url(), account_email)
        });
    if let Err(error) = admission {
        retire_unpublished_response(
            runtime,
            stopped,
            client,
            bearer_token,
            &record,
            &slot.account_key,
        )
        .await?;
        refresh_pending(runtime);
        return Err(error);
    }
    // The request predates HTTP and fences both another sync pass and native
    // removal until this publication or retirement is durably terminal.
    let mut operation = match begin_login_publication(stopped) {
        Ok(operation) => operation,
        Err(error) => {
            retire_unpublished_response(
                runtime,
                stopped,
                client,
                bearer_token,
                &record,
                &slot.account_key,
            )
            .await?;
            refresh_pending(runtime);
            return Err(error);
        }
    };
    let mut state = prepare_candidate_state(&runtime.coordinator.snapshot(), &record, Utc::now())?;
    runtime.remember_candidate_recovery_record(&record);
    runtime.set_candidate_recovery_pending(true);
    runtime.store.save(&state)?;
    operation.publish_persisted_state(state.clone())?;
    write_exact(
        &PendingMacOsCredentialStore,
        &slot.account_key,
        bearer_token,
    )?;
    recover_prior_candidates(
        runtime,
        &mut state,
        client,
        bearer_token,
        &identity,
        &record,
    )
    .await?;
    runtime.store.save(&state)?;
    retire_prior_sessions(runtime, &identity, bearer_token).await?;
    if !runtime.auth_offboarding.may_publish(generation) {
        let retired = retire_staged_candidate(
            runtime,
            &mut state,
            client,
            bearer_token,
            &record,
            &slot.account_key,
        )
        .await;
        operation.finish_state(state);
        retired?;
        refresh_pending(runtime);
        return Err(canceled_sign_in());
    }
    state.publish_active_remote_session(record.clone());
    runtime.store.save(&state)?;
    if !runtime.auth_offboarding.may_publish(generation) {
        let retired = retire_staged_candidate(
            runtime,
            &mut state,
            client,
            bearer_token,
            &record,
            &slot.account_key,
        )
        .await;
        operation.finish_state(state);
        retired?;
        refresh_pending(runtime);
        return Err(canceled_sign_in());
    }
    write_exact(
        runtime.platform.credentials(),
        &identity.credential_key(),
        bearer_token,
    )?;
    remove_exact(&PendingMacOsCredentialStore, &slot.account_key)?;
    let retained_slots = owned_pending_keys(&state)?;
    persist_converged_candidate_state(&mut state, retained_slots, |persisted| {
        runtime.store.save(persisted)
    })?;
    *runtime.session.lock().expect("session lock") = Some(identity);
    operation.finish_state(state);
    runtime.set_candidate_recovery_pending(false);
    Ok(())
}

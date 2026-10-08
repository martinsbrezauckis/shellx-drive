//! Durable remote-session retirement around mandatory local secret deletion.

#[path = "remote_revocations/direct_retirement.rs"]
mod direct_retirement;
#[path = "remote_revocations/prior_candidates.rs"]
mod prior_candidates;
#[path = "remote_revocations/staged_candidate.rs"]
mod staged_candidate;

use super::{pending_session_retirement::*, *};
use crate::application::candidate_admission::prepare_candidate_state;
use direct_retirement::retire_bearer;
use prior_candidates::retire_prior_candidate_sessions;

pub(super) use staged_candidate::{remove_staged_candidate, stage_pending_candidate};

pub(super) fn remove_staged_slot(slot: &ServiceCredentialKey) -> CoreResult<()> {
    staged_candidate::remove_staged_slot(slot)
}

pub(super) async fn retire_unpublished_session(
    runtime: &Runtime,
    stopped: &mut DisconnectRequest,
    client: &DriveHttpClient,
    bearer_token: &str,
    account_email: &str,
    session_id: &str,
    expires_at: chrono::DateTime<Utc>,
) -> CoreResult<()> {
    let record = RemoteSessionRecord::new(
        client.normalized_url(),
        account_email,
        session_id,
        expires_at,
    )?;
    if client.logout(bearer_token).await.is_err() {
        // A crash or a provider error after a pending-slot write must still
        // leave a non-secret locator for startup and future same-identity
        // recovery. Persist it before touching Credential Manager.
        runtime.remember_candidate_recovery_record(&record);
        runtime.set_candidate_recovery_pending(true);
        let mut operation = stopped.try_begin()?.ok_or_else(|| {
            DesktopError::InvalidState(
                "Drive synchronization has not stopped for sign-in cleanup".to_string(),
            )
        })?;
        let state = prepare_candidate_state(&runtime.coordinator.snapshot(), &record, Utc::now())?;
        runtime.store.save(&state)?;
        operation.publish_persisted_state(state.clone())?;
        let staged = stage_pending_candidate(client, bearer_token, &record);
        operation.finish_state(state);
        staged?;
    }
    Ok(())
}

/// Durable candidate staging precedes any replacement retirement. The pending
/// record supplies a future same-identity authorizer if a later step fails.
pub(super) fn stage_candidate_for_publication(
    runtime: &Runtime,
    state: &mut DesktopState,
    client: &DriveHttpClient,
    bearer_token: &str,
    record: &RemoteSessionRecord,
) -> CoreResult<()> {
    // Save the locator first. A pending credential write can report an error
    // after committing, so this ordering leaves a durable recovery record for
    // either outcome without publishing into the canonical namespace.
    runtime.remember_candidate_recovery_record(record);
    runtime.set_candidate_recovery_pending(true);
    *state = prepare_candidate_state(state, record, Utc::now())?;
    runtime.store.save(state)?;
    stage_pending_candidate(client, bearer_token, record)
}

pub(super) async fn retire_canceled_login(
    runtime: &Runtime,
    stopped: &mut DisconnectRequest,
    client: &DriveHttpClient,
    outcome: &LoginOutcome,
) -> CoreResult<()> {
    if let LoginOutcome::Authenticated {
        bearer_token,
        account_email,
        session_id,
        expires_at,
        ..
    } = outcome
    {
        retire_unpublished_session(
            runtime,
            stopped,
            client,
            bearer_token,
            account_email,
            session_id,
            *expires_at,
        )
        .await?;
    }
    Ok(())
}

/// Save retry metadata only after every known session can still be retired by
/// a retained local credential. Credential deletion happens in the caller
/// after it has durably stored the candidate bearer.
pub(super) async fn retire_stored_credentials(
    runtime: &Runtime,
    state: &mut DesktopState,
    fallback: Option<&SessionIdentity>,
    candidate: Option<(
        &SessionIdentity,
        &DriveHttpClient,
        &str,
        &RemoteSessionRecord,
    )>,
) -> CoreResult<()> {
    if let Some((identity, client, bearer_token, record)) = candidate {
        retire_prior_candidate_sessions(runtime, state, identity, record, client, bearer_token)
            .await?;
    }
    let stored = stored_session_credentials(runtime, state, fallback)?;
    let direct_retirements = direct_retirement_records(state, &stored);
    let direct_records = direct_retirements
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();

    let preferred_authorizer = candidate.map(|(identity, _, bearer_token, _)| {
        StoredSessionCredential::candidate(identity, bearer_token)
    });
    retire_pending_remote_sessions(
        state,
        &stored,
        preferred_authorizer.as_ref(),
        candidate.map(|(_, _, _, record)| record),
        &direct_records,
        false,
    )
    .await?;

    // Every non-direct pending record was revoked while its matching stored
    // bearer was still valid. Persist that progress before invalidating any
    // fallback bearer needed by a different server/account on a retry.
    runtime.store.save(state)?;
    for (credential, direct_retirement) in stored.iter().zip(&direct_retirements) {
        if stored_credential_needs_remote_retirement(
            &credential.identity,
            &credential.bearer_token,
            candidate.map(|(identity, _, token, _)| (identity, token)),
        ) {
            retire_bearer(state, credential, direct_retirement.as_ref()).await?;
            // Logout accepts an already-invalid bearer. Saving after every
            // direct retirement makes a failed save retry-safe without ever
            // using that invalid bearer for a session-revocation request.
            runtime.store.save(state)?;
        }
    }

    if let Some((_, _, _, record)) = candidate {
        state.publish_active_remote_session(record.clone());
    } else {
        state.active_remote_session = None;
    }
    runtime.store.save(state)
}

pub(super) async fn retire_failed_candidate(
    runtime: &Runtime,
    state: &mut DesktopState,
    client: &DriveHttpClient,
    bearer_token: &str,
    record: &RemoteSessionRecord,
) -> CoreResult<()> {
    match client.logout(bearer_token).await {
        Ok(_) => {
            // Keep the exact durable locator until local deletion/readback
            // succeeds, including when the retired session has expired.
            runtime.remember_candidate_recovery_record(record);
            runtime.set_candidate_recovery_pending(true);
            remove_staged_candidate(record)?;
            let persisted = state_after_confirmed_remote_retirement(state, record);
            runtime.store.save(&persisted)?;
            *state = persisted;
            Ok(())
        }
        Err(_) => {
            // Keep a durable non-secret locator before a fallible staged write
            // so an ambiguous provider result is recoverable on the next
            // serialized startup.
            runtime.remember_candidate_recovery_record(record);
            runtime.set_candidate_recovery_pending(true);
            if state
                .active_remote_session
                .as_ref()
                .is_some_and(|active| active.same_remote_session(record))
            {
                state.active_remote_session = None;
            }
            state.pending_candidate_session = Some(record.clone());
            runtime.store.save(state)?;
            stage_pending_candidate(client, bearer_token, record)?;
            runtime.store.save(state)
        }
    }
}

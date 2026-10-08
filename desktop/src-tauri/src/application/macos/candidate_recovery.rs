//! Keychain pending-candidate publication and interrupted-login recovery.
//!
//! Bearers never enter durable state. A pending Keychain slot plus its
//! non-secret remote-session locator is persisted before canonical replacement.

mod cancellation;
mod prior;

use chrono::Utc;
use shellx_drive_desktop_core::{
    classify_exact_credential_removal, classify_exact_credential_write, CredentialStore,
    DesktopError, DriveHttpClient, ExactCredentialRemoval, ExactCredentialWrite, LogoutOutcome,
    MacOsCredentialStore, PendingMacOsCredentialStore, RemoteSessionRecord, Result as CoreResult,
    CANDIDATE_RECOVERY_PAUSED_ERROR,
};

use super::*;
use crate::application::auth_publication::canceled_sign_in;
use crate::application::unix_candidate_recovery::{
    ordered_slots, persist_converged_candidate_state, recover_slot, RecoveryStores,
    RemoteRecoveryAction,
};
use crate::session_identity::SessionIdentity;
use cancellation::{refresh_pending, retire_staged_candidate, retire_unpublished_response};
use prior::recover_prior_candidates;

pub(super) fn recover_at_startup(runtime: &Runtime) {
    let result = tauri::async_runtime::block_on(async {
        let _publication = runtime.auth_publication.lock().await;
        let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
        let mut state = runtime.coordinator.snapshot();
        let mut result = recover(runtime, &mut state).await;
        if result.is_ok() && state.clear_candidate_recovery_error() {
            if let Err(error) = runtime.store.save(&state) {
                result = Err(error);
            }
        }
        operation.finish_state(state);
        result
    });
    runtime.set_candidate_recovery_pending(result.is_err());
    if result.is_err() {
        runtime
            .coordinator
            .record_error(CANDIDATE_RECOVERY_PAUSED_ERROR);
        let _ = runtime.save();
    }
}

pub(super) fn require_login_identity(
    runtime: &Runtime,
    normalized_url: &str,
    email: &str,
) -> CoreResult<()> {
    if !runtime.candidate_recovery_pending() {
        return Ok(());
    }
    let requested = SessionIdentity::credential_key_for(normalized_url, email);
    let state_matches =
        shellx_drive_desktop_core::candidate_recovery_locator(&runtime.coordinator.snapshot())
            .is_some_and(|record| {
                SessionIdentity::credential_key_for(&record.server_url, &record.account_email)
                    == requested
            });
    let staged_matches = PendingMacOsCredentialStore::service_account_keys()?
        .into_iter()
        .filter_map(|key| SessionIdentity::parse_pending_service_key(&key))
        .any(|slot| slot.identity.credential_key() == requested);
    if state_matches || staged_matches {
        Ok(())
    } else {
        Err(DesktopError::Credential(
            "Drive credential recovery permits sign-in only for its retained server and account"
                .to_string(),
        ))
    }
}

pub(super) async fn publish_authenticated_session(
    runtime: &Runtime,
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
        retire_unpublished_response(runtime, client, bearer_token, &record, &slot.account_key)
            .await?;
        refresh_pending(runtime);
        return Err(canceled_sign_in());
    }
    runtime.ensure_login_matches_retained_pair(client.normalized_url(), account_email)?;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let mut state = runtime.coordinator.snapshot();
    runtime.set_candidate_recovery_pending(true);
    state.record_pending_candidate_session(record.clone(), Utc::now());
    runtime.store.save(&state)?;
    operation.publish_persisted_state(state.clone())?;
    write_exact(
        &PendingMacOsCredentialStore,
        &slot.account_key,
        bearer_token,
    )?;
    recover_prior_candidates(&mut state, client, bearer_token, &identity, &record).await?;
    runtime.store.save(&state)?;
    retire_prior_sessions(&identity, bearer_token).await?;
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
    MacOsCredentialStore::delete_service_credentials_except(&identity.credential_key())?;
    remove_exact(&PendingMacOsCredentialStore, &slot.account_key)?;
    persist_converged_candidate_state(
        &mut state,
        PendingMacOsCredentialStore::service_account_keys()?,
        |persisted| runtime.store.save(persisted),
    )?;
    *runtime.session.lock().expect("session lock") = Some(identity);
    operation.finish_state(state);
    runtime.set_candidate_recovery_pending(false);
    Ok(())
}

async fn recover(
    runtime: &Runtime,
    state: &mut shellx_drive_desktop_core::DesktopState,
) -> CoreResult<()> {
    let slots = PendingMacOsCredentialStore::service_account_keys()?;
    if slots.is_empty() && state.pending_candidate_session.is_none() {
        return Ok(());
    }
    for slot in ordered_slots(state, slots)? {
        let bearer = PendingMacOsCredentialStore
            .get(&slot.account_key)?
            .ok_or_else(candidate_error)?;
        let identity = &slot.identity;
        let bearer = bearer.as_str();
        recover_slot(
            state,
            &slot,
            bearer,
            RecoveryStores {
                canonical: runtime.platform.credentials(),
                pending: &PendingMacOsCredentialStore,
            },
            |persisted| runtime.store.save(persisted),
            |action| async move {
                match action {
                    RemoteRecoveryAction::RetireCandidate => {
                        DriveHttpClient::new(&identity.server_url)?
                            .logout(bearer)
                            .await
                            .map(|outcome| match outcome {
                                LogoutOutcome::Revoked | LogoutOutcome::AlreadyInvalid => (),
                            })
                            .map_err(|_| candidate_error())
                    }
                    RemoteRecoveryAction::RetirePriorCanonical => {
                        retire_prior_sessions(identity, bearer).await
                    }
                }
            },
            || MacOsCredentialStore::delete_service_credentials_except(&identity.credential_key()),
        )
        .await?;
    }
    if state.pending_candidate_session.is_some() {
        return Err(candidate_error());
    }
    Ok(())
}

async fn retire_prior_sessions(
    candidate: &SessionIdentity,
    candidate_bearer: &str,
) -> CoreResult<()> {
    for account_key in MacOsCredentialStore::service_account_keys()? {
        let Some(identity) = SessionIdentity::parse_canonical_credential_key(&account_key) else {
            return Err(candidate_error());
        };
        let Some(bearer) = MacOsCredentialStore.get(&account_key)? else {
            return Err(candidate_error());
        };
        if identity.credential_key() == candidate.credential_key() && bearer == candidate_bearer {
            continue;
        }
        let client = DriveHttpClient::new(&identity.server_url)?;
        client
            .logout(&bearer)
            .await
            .map_err(|_| candidate_error())?;
    }
    Ok(())
}

fn write_exact(store: &dyn CredentialStore, key: &str, bearer: &str) -> CoreResult<()> {
    match classify_exact_credential_write(store.set(key, bearer), store.get(key), bearer) {
        ExactCredentialWrite::Written => Ok(()),
        ExactCredentialWrite::NotWritten | ExactCredentialWrite::Unknown => Err(candidate_error()),
    }
}

fn remove_exact(store: &dyn CredentialStore, key: &str) -> CoreResult<()> {
    match classify_exact_credential_removal(store.delete(key), store.get(key)) {
        ExactCredentialRemoval::Removed => Ok(()),
        ExactCredentialRemoval::Retained | ExactCredentialRemoval::Unknown => {
            Err(candidate_error())
        }
    }
}

fn candidate_error() -> DesktopError {
    DesktopError::Credential(
        "Drive credential recovery needs retry; credentials were kept for retry".to_string(),
    )
}

//! Linux password and second-factor sign-in commands.
//!
//! Bearers are held only in the native request and Secret Service.  A
//! successful server response is staged in the dedicated pending service
//! before the canonical service changes, so an ambiguous keyring write never
//! silently replaces the retained credential.

pub(super) mod cancellation;
mod recovery;

use chrono::Utc;
use serde::Serialize;
use shellx_drive_desktop_core::{
    classify_exact_credential_removal, classify_exact_credential_write, CredentialStore,
    DesktopError, DisconnectRequest, DriveHttpClient, ExactCredentialRemoval, ExactCredentialWrite,
    LinuxCredentialStore, LoginOutcome, PendingLinuxCredentialStore, RemoteSessionRecord,
    Result as CoreResult,
};
use tauri::{AppHandle, State};

use crate::{
    application::{
        auth_publication::{canceled_sign_in, publish_second_factor},
        connections::ConnectionManager,
        PendingLogin, Runtime,
    },
    session_identity::SessionIdentity,
};

use super::shell::update_tray;
use cancellation::{retire_staged_candidate, retire_unpublished_response};
use recovery::recover_prior_candidates;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LoginReply {
    kind: &'static str,
    account_email: String,
}

#[tauri::command]
pub(super) async fn login_password(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    server_url: String,
    email: String,
    password: String,
) -> Result<LoginReply, String> {
    manager.ensure_mutation_allowed().map_err(present_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(present_error)?;
    let client = DriveHttpClient::new(&server_url).map_err(present_error)?;
    runtime
        .require_linux_candidate_recovery_identity(client.normalized_url(), &email)
        .map_err(present_error)?;
    let generation = runtime
        .auth_offboarding
        .admit_login()
        .map_err(present_error)?;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    runtime
        .ensure_login_matches_retained_pair(client.normalized_url(), &email)
        .map_err(present_error)?;
    // A saved connection can renew sign-in while it is syncing. Stop only
    // that pass before issuing a session and retain the coordinator request
    // through publication, so a response cannot become an untracked bearer
    // merely because another pass started in the meantime.
    let mut stopped = crate::application::request_disconnect_after_sync(&runtime)
        .await
        .map_err(present_error)?;
    if !runtime.auth_offboarding.may_publish(generation) {
        return Err(present_error(canceled_sign_in()));
    }
    crate::application::candidate_admission::ensure_candidate_admission(
        &runtime.coordinator.snapshot(),
    )
    .map_err(present_error)?;
    match client
        .login_password(&email, &password)
        .await
        .map_err(present_error)?
    {
        LoginOutcome::Authenticated {
            bearer_token,
            account_email,
            session_id,
            expires_at,
            ..
        } => {
            publish_authenticated_session(
                &runtime,
                &manager,
                &mut stopped,
                &client,
                &bearer_token,
                &account_email,
                &session_id,
                expires_at,
                generation,
            )
            .await
            .map_err(present_error)?;
            update_tray(&app, &runtime);
            Ok(LoginReply {
                kind: "authenticated",
                account_email,
            })
        }
        LoginOutcome::RequiresSecondFactor { account_email } => {
            runtime
                .ensure_login_matches_retained_pair(client.normalized_url(), &account_email)
                .map_err(present_error)?;
            publish_second_factor(
                &runtime.auth_offboarding,
                &runtime.auth_publication,
                &runtime.pending_login,
                PendingLogin {
                    server_url: client.normalized_url().to_string(),
                    email: account_email.clone(),
                    password,
                    generation,
                },
            )
            .await
            .map_err(present_error)?;
            Ok(LoginReply {
                kind: "requires_second_factor",
                account_email,
            })
        }
    }
}

#[tauri::command]
pub(super) async fn continue_login(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    email: String,
    password: String,
    totp_code: Option<String>,
    recovery_code: Option<String>,
) -> Result<LoginReply, String> {
    manager.ensure_mutation_allowed().map_err(present_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(present_error)?;
    let pending = runtime
        .pending_login
        .lock()
        .expect("pending login lock")
        .take()
        .ok_or_else(|| {
            "Start with password sign-in before entering a second factor.".to_string()
        })?;
    if pending.email != email || pending.password != password {
        return Err("Password sign-in changed; start sign-in again.".to_string());
    }
    if !runtime.auth_offboarding.may_publish(pending.generation) {
        return Err("Sign-in was canceled; start sign-in again.".to_string());
    }
    let client = DriveHttpClient::new(&pending.server_url).map_err(present_error)?;
    runtime
        .require_linux_candidate_recovery_identity(client.normalized_url(), &email)
        .map_err(present_error)?;
    runtime
        .ensure_login_matches_retained_pair(client.normalized_url(), &email)
        .map_err(present_error)?;
    let mut stopped = crate::application::request_disconnect_after_sync(&runtime)
        .await
        .map_err(present_error)?;
    if !runtime.auth_offboarding.may_publish(pending.generation) {
        return Err(present_error(canceled_sign_in()));
    }
    crate::application::candidate_admission::ensure_candidate_admission(
        &runtime.coordinator.snapshot(),
    )
    .map_err(present_error)?;
    match client
        .continue_login(
            &email,
            &password,
            totp_code.as_deref(),
            recovery_code.as_deref(),
        )
        .await
        .map_err(present_error)?
    {
        LoginOutcome::Authenticated {
            bearer_token,
            account_email,
            session_id,
            expires_at,
            ..
        } => {
            publish_authenticated_session(
                &runtime,
                &manager,
                &mut stopped,
                &client,
                &bearer_token,
                &account_email,
                &session_id,
                expires_at,
                pending.generation,
            )
            .await
            .map_err(present_error)?;
            update_tray(&app, &runtime);
            Ok(LoginReply {
                kind: "authenticated",
                account_email,
            })
        }
        LoginOutcome::RequiresSecondFactor { account_email } => Err(format!(
            "Drive still requires a second factor for {account_email}. Enter one current code."
        )),
    }
}

// Keep the transaction's runtime, cancellation and authenticated response inputs explicit.
#[allow(clippy::too_many_arguments)]
async fn publish_authenticated_session(
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
    let canonical_key = identity.credential_key();
    let pending_key = identity.pending_service_key(session_id).ok_or_else(|| {
        DesktopError::Credential("Drive returned an invalid session identifier".to_string())
    })?;
    let record = RemoteSessionRecord::new(
        client.normalized_url(),
        account_email,
        session_id,
        expires_at,
    )?;

    // Keep the terminal serializer through both the freshness decision and
    // any stale-response retirement. A newer login or Disconnect therefore
    // cannot publish while this response is being safely retired.
    let _publication = runtime.auth_publication.lock().await;
    if !runtime.auth_offboarding.may_publish(generation) {
        retire_unpublished_response(
            runtime,
            stopped,
            client,
            bearer_token,
            &record,
            &pending_key.account_key,
        )
        .await?;
        runtime.refresh_linux_candidate_recovery_pending();
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
        // A duplicate owns this newly issued session only. Never stage or
        // retire the other connection's canonical bearer.
        retire_unpublished_response(
            runtime,
            stopped,
            client,
            bearer_token,
            &record,
            &pending_key.account_key,
        )
        .await?;
        runtime.refresh_linux_candidate_recovery_pending();
        return Err(error);
    }

    // Persist only the non-secret recovery locator before the pending write.
    // A provider error after committing a Secret Service update must block
    // sync rather than let a later operation guess which bearer survived.
    let mut operation = stopped.try_begin()?.ok_or_else(|| {
        DesktopError::InvalidState("Drive synchronization has not stopped for sign-in".to_string())
    })?;
    let mut state = crate::application::candidate_admission::prepare_candidate_state(
        &runtime.coordinator.snapshot(),
        &record,
        Utc::now(),
    )?;
    runtime.store.save(&state)?;
    operation.publish_persisted_state(state.clone())?;
    runtime.remember_candidate_recovery_record(&record);
    runtime.set_candidate_recovery_pending(true);

    let pending = PendingLinuxCredentialStore;
    let staged = pending.set(&pending_key.account_key, bearer_token);
    let staged_readback = pending.get(&pending_key.account_key);
    if !matches!(
        classify_exact_credential_write(staged, staged_readback, bearer_token),
        ExactCredentialWrite::Written
    ) {
        operation.finish_state(state);
        return Err(DesktopError::Credential(
            "Drive credential staging was not confirmed; credentials were kept for recovery."
                .to_string(),
        ));
    }

    recover_prior_candidates(
        runtime,
        &mut state,
        &pending,
        client,
        bearer_token,
        &identity,
        &record,
    )
    .await?;
    runtime.store.save(&state)?;

    // Retire only this connection's prior canonical session. Other accounts
    // retain their credentials and pending recovery candidates.
    let canonical = LinuxCredentialStore;
    if let Some(previous) = canonical.get(&canonical_key)? {
        if previous != bearer_token {
            client.logout(&previous).await.map_err(|_| {
                DesktopError::Credential(
                    "remote session retirement was not confirmed; credentials were kept for retry"
                        .to_string(),
                )
            })?;
        }
    }

    // `admit_login` does not wait for an already-running network response.
    // Recheck while holding the terminal serializer immediately before any
    // canonical Secret Service write. Disconnect waits on this serializer,
    // then retires the exact staged candidate through its cleanup journal.
    if !runtime.auth_offboarding.may_publish(generation) {
        let retired = retire_staged_candidate(
            runtime,
            &mut state,
            client,
            bearer_token,
            &record,
            &pending_key.account_key,
        )
        .await;
        operation.finish_state(state);
        retired?;
        runtime.refresh_linux_candidate_recovery_pending();
        return Err(canceled_sign_in());
    }

    let written = canonical.set(&canonical_key, bearer_token);
    let written_readback = canonical.get(&canonical_key);
    if !matches!(
        classify_exact_credential_write(written, written_readback, bearer_token),
        ExactCredentialWrite::Written
    ) {
        operation.finish_state(state);
        return Err(DesktopError::Credential(
            "Drive credential publication was not confirmed; credentials were kept for recovery."
                .to_string(),
        ));
    }
    let removed = pending.delete(&pending_key.account_key);
    let removed_readback = pending.get(&pending_key.account_key);
    if !matches!(
        classify_exact_credential_removal(removed, removed_readback),
        ExactCredentialRemoval::Removed
    ) {
        operation.finish_state(state);
        return Err(DesktopError::Credential(
            "Drive staged credential cleanup was not confirmed; sync remains paused for recovery."
                .to_string(),
        ));
    }

    state.publish_active_remote_session(record);
    let remaining_slots = super::candidate::owned_pending_keys(&state)?;
    crate::application::unix_candidate_recovery::persist_converged_candidate_state(
        &mut state,
        remaining_slots,
        |persisted| runtime.store.save(persisted),
    )?;
    operation.finish_state(state);
    *runtime.session.lock().expect("session lock") = Some(identity);
    runtime.set_candidate_recovery_pending(false);
    Ok(())
}

fn present_error(error: DesktopError) -> String {
    error.to_string()
}

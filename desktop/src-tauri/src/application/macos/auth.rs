//! Password and second-factor admission for the macOS desktop shell.

use chrono::Utc;
use serde::Serialize;
use shellx_drive_desktop_core::{DisconnectRequest, DriveHttpClient, LoginOutcome};
use tauri::State;

use super::*;
use crate::application::auth_publication::publish_second_factor;
use crate::application::candidate_admission::ensure_candidate_admission;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LoginReply {
    kind: &'static str,
    account_email: String,
}

#[tauri::command]
pub(super) async fn login_password(
    app: tauri::AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    server_url: String,
    email: String,
    password: String,
) -> Result<LoginReply, String> {
    manager.ensure_mutation_allowed().map_err(macos_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(macos_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(macos_error)?;
    let client = DriveHttpClient::new(&server_url).map_err(macos_error)?;
    let generation = runtime
        .auth_offboarding
        .admit_login()
        .map_err(macos_error)?;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    candidate_recovery::require_login_identity(&runtime, client.normalized_url(), &email)
        .map_err(macos_error)?;
    runtime
        .ensure_login_matches_retained_pair(client.normalized_url(), &email)
        .map_err(macos_error)?;
    // Keep this exact stop request through the server response and terminal
    // publication so removal cannot discard late-session recovery ownership.
    let mut stopped = crate::application::request_disconnect_after_sync(&runtime)
        .await
        .map_err(macos_error)?;
    if !runtime.auth_offboarding.may_publish(generation) {
        return Err("Sign-in was canceled; start sign-in again.".to_string());
    }
    ensure_candidate_admission(&runtime.coordinator.snapshot()).map_err(macos_error)?;
    let outcome = async {
        Ok::<_, DesktopError>((
            client.clone(),
            client.login_password(&email, &password).await?,
        ))
    }
    .await
    .map_err(macos_error)?;
    finish_login(
        &app,
        &runtime,
        &manager,
        &mut stopped,
        outcome.0,
        outcome.1,
        Some(password),
        generation,
    )
    .await
}

#[tauri::command]
pub(super) async fn continue_login(
    app: tauri::AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    email: String,
    password: String,
    totp_code: Option<String>,
    recovery_code: Option<String>,
) -> Result<LoginReply, String> {
    manager.ensure_mutation_allowed().map_err(macos_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(macos_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(macos_error)?;
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
    let client = DriveHttpClient::new(&pending.server_url).map_err(macos_error)?;
    candidate_recovery::require_login_identity(&runtime, client.normalized_url(), &email)
        .map_err(macos_error)?;
    runtime
        .ensure_login_matches_retained_pair(client.normalized_url(), &email)
        .map_err(macos_error)?;
    let mut stopped = crate::application::request_disconnect_after_sync(&runtime)
        .await
        .map_err(macos_error)?;
    if !runtime.auth_offboarding.may_publish(pending.generation) {
        return Err("Sign-in was canceled; start sign-in again.".to_string());
    }
    ensure_candidate_admission(&runtime.coordinator.snapshot()).map_err(macos_error)?;
    let outcome = async {
        Ok::<_, DesktopError>((
            client.clone(),
            client
                .continue_login(
                    &email,
                    &password,
                    totp_code.as_deref(),
                    recovery_code.as_deref(),
                )
                .await?,
        ))
    }
    .await
    .map_err(macos_error)?;
    finish_login(
        &app,
        &runtime,
        &manager,
        &mut stopped,
        outcome.0,
        outcome.1,
        None,
        pending.generation,
    )
    .await
}

async fn finish_login(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    manager: &ConnectionManager,
    stopped: &mut DisconnectRequest,
    client: DriveHttpClient,
    outcome: LoginOutcome,
    password_for_second_factor: Option<String>,
    generation: u64,
) -> Result<LoginReply, String> {
    match outcome {
        LoginOutcome::Authenticated {
            bearer_token,
            account_email,
            session_id,
            expires_at,
            ..
        } => {
            candidate_recovery::publish_authenticated_session(
                runtime,
                manager,
                stopped,
                &client,
                &bearer_token,
                &account_email,
                &session_id,
                expires_at,
                generation,
            )
            .await
            .map_err(macos_error)?;
            shell::update_tray(app, runtime);
            Ok(LoginReply {
                kind: "authenticated",
                account_email,
            })
        }
        LoginOutcome::RequiresSecondFactor { account_email } => {
            let password = password_for_second_factor.ok_or_else(|| {
                "Drive still requires a second factor. Start password sign-in again.".to_string()
            })?;
            runtime
                .ensure_login_matches_retained_pair(client.normalized_url(), &account_email)
                .map_err(macos_error)?;
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
            .map_err(macos_error)?;
            Ok(LoginReply {
                kind: "requires_second_factor",
                account_email,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_factor_reply_has_no_secret_fields() {
        let value = serde_json::to_string(&LoginReply {
            kind: "requires_second_factor",
            account_email: "person@example.test".to_string(),
        })
        .unwrap();
        assert!(!value.contains("password"));
        assert!(!value.contains("token"));
    }
}

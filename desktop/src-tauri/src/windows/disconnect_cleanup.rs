//! Durable local half of normal Disconnect after remote retirement succeeds.

use super::*;

#[path = "disconnect_cleanup/local.rs"]
mod local;
pub(crate) use local::{
    complete_local_cleanup_with_finalizer, complete_pending_local_cleanup,
    persist_disconnect_cleanup_intent, resume_disconnected_local_cleanup, scoped_credential_slots,
    DISCONNECT_CLEANUP_PENDING_ERROR,
};

pub(crate) async fn disconnect_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
) -> Result<DesktopView, String> {
    app.state::<ConnectionManager>()
        .ensure_mutation_allowed()
        .map_err(user_error)?;
    if crate::application::desktop_agent::pending_disconnect_requires_capability_retry(runtime) {
        return crate::application::desktop_agent::retry_pending_disconnect_completion(
            app, runtime,
        )
        .await
        .map(|_| runtime.view())
        .map_err(user_error);
    }
    let _offboarding = runtime
        .auth_offboarding
        .begin_offboarding()
        .map_err(user_error)?;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    let mut disconnect = crate::application::request_disconnect_after_sync(runtime)
        .await
        .map_err(user_error)?;
    let _auth_publication = runtime.auth_publication.lock().await;
    // The operation spans remote retirement and the local durable journal so
    // another lifecycle action cannot observe a half-disconnected state.
    let mut operation = disconnect.try_begin().map_err(user_error)?.ok_or_else(|| {
        user_error(DesktopError::InvalidState(
            "synchronization restarted while Disconnect was pending".to_string(),
        ))
    })?;
    let mut state = runtime.coordinator.snapshot();

    if let Err(error) = persist_disconnect_cleanup_intent(runtime, &mut state) {
        return Err(user_error(error));
    }
    operation
        .publish_persisted_state(state.clone())
        .map_err(user_error)?;
    let remote_retirement_confirmed = state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed);
    if !remote_retirement_confirmed {
        if let Err(error) =
            crate::application::desktop_agent::freeze_for_pending_disconnect(runtime).await
        {
            operation.finish_state(state);
            update_tray(app, runtime);
            return Err(user_error(error));
        }
    }
    // Once the intent is durable and the broker is frozen, no poll may use a
    // credential while Disconnect is awaiting remote or local cleanup recovery.
    stop_polling(runtime);

    let local_cleanup_only = state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
        && state.pair.is_none();
    if !local_cleanup_only {
        if let Err(error) =
            crate::application::desktop_agent::revoke_for_pending_disconnect(runtime, &mut state)
                .await
        {
            operation.finish_state(state);
            update_tray(app, runtime);
            return Err(user_error(error));
        }
        if let Err(error) = operation.publish_persisted_state(state.clone()) {
            operation.finish_state(state);
            update_tray(app, runtime);
            return Err(user_error(error));
        }
        let session = runtime.session.lock().expect("session lock").clone();
        let retained_pair_identity = state
            .pair
            .as_ref()
            .map(|pair| SessionIdentity::new(pair.server_url.clone(), pair.account_email.clone()));
        let identity = disconnect_identity(session, retained_pair_identity);
        if let Err(error) = disconnect_credentials(runtime, &mut state, identity.as_ref()).await {
            // The intent remains durable and the retained pair keeps all
            // credentials until a later Disconnect proves remote retirement.
            operation.finish_state(state);
            update_tray(app, runtime);
            return Err(user_error(error));
        }

        let mut disconnected = state.clone();
        disconnected
            .pending_disconnect_cleanup_mut()
            .ok_or_else(|| {
                user_error(DesktopError::InvalidState(
                    "disconnect cleanup was not pending after remote retirement".to_string(),
                ))
            })?
            .confirm_remote_retirement();
        let disconnected = disconnected.into_disconnected(Utc::now());
        if let Err(error) = runtime.store.save(&disconnected) {
            // Remote retirement is irreversible, but no local deletion has
            // begun. Keep the persisted intent and retained pair for a safe
            // retry that treats an already-invalid remote session as success.
            operation.finish_state(state);
            *runtime.session.lock().expect("session lock") = None;
            invalidate_pending_confirmation(runtime);
            update_tray(app, runtime);
            return Err(user_error(error));
        }
        state = disconnected;
        operation
            .publish_persisted_state(state.clone())
            .map_err(user_error)?;
        *runtime.session.lock().expect("session lock") = None;
        invalidate_pending_confirmation(runtime);
    }

    if let Err(error) = complete_pending_local_cleanup(&runtime.store, &mut state) {
        // State remains disconnected with the unacknowledged exact operation
        // at its head, so start-up or a repeated Disconnect can safely resume.
        operation.finish_state(state);
        update_tray(app, runtime);
        return Err(user_error(error));
    }

    operation.finish_state(state);
    runtime.refresh_candidate_recovery_pending();
    *runtime.session.lock().expect("session lock") = None;
    *runtime.pending_login.lock().expect("pending login lock") = None;
    invalidate_pending_confirmation(runtime);
    update_tray(app, runtime);
    Ok(runtime.view())
}

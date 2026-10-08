use axum::response::Response;

use crate::auth::{Actor, DriveCredential};

/// An internal-only result marker for a verified self-disable or self-demotion.
/// It is an Axum extension, never an HTTP header or serialized body field.
#[derive(Clone, Debug)]
struct AdminSelfRemovalCompletion {
    actor_email: String,
    target_email: String,
    source_credential: DriveCredential,
    security_version: i64,
    source_credential_was_revoked: bool,
}

pub(crate) fn mark_admin_self_removal_completion(
    response: &mut Response,
    actor: &Actor,
    target_email: &str,
    source_credential: &DriveCredential,
    security_version: i64,
    source_credential_was_revoked: bool,
) {
    response
        .extensions_mut()
        .insert(AdminSelfRemovalCompletion {
            actor_email: actor.email.clone(),
            target_email: target_email.to_string(),
            source_credential: source_credential.clone(),
            security_version,
            source_credential_was_revoked,
        });
}

/// A role or account loss caused by this exact guarded action may publish its
/// own bounded result. Other admin responses still require live admin status.
pub(super) fn is_self_removal_completion(
    state: &crate::server::AppState,
    path: &str,
    response: &Response,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> bool {
    path.starts_with("/admin/auth/users/")
        && response
            .extensions()
            .get::<AdminSelfRemovalCompletion>()
            .is_some_and(|completion| {
                completion.actor_email == actor.email
                    && completion.target_email == actor.email
                    && completion.source_credential == *source_credential
                    && state
                        .storage
                        .ensure_self_removal_completion_authorized(
                            actor,
                            source_credential,
                            completion.security_version,
                            completion.source_credential_was_revoked,
                        )
                        .is_ok()
            })
}

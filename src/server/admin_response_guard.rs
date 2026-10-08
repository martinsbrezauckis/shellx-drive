//! Terminal authorization for buffered administrative JSON responses.
//!
//! Admin and debug handlers may collect several records (or await bounded
//! background work) before Axum publishes their JSON body. The entry check in
//! each handler deliberately remains the admission check; this middleware is
//! the distinct terminal publication check so a source-session revocation or
//! local-admin demotion that commits during collection wins before the body is
//! sent.

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    auth::{require_admin_with_credential, Actor, DriveCredential},
    error::ApiResult,
    server::AppState,
};

mod self_removal_completion;
use self_removal_completion::is_self_removal_completion;
pub(crate) use self_removal_completion::mark_admin_self_removal_completion;

/// Revalidate the exact bearer credential at the terminal point for buffered
/// account-wide administration JSON. Binary backup bodies retain their
/// purpose-built publication intents and are intentionally not covered here.
pub(crate) async fn revalidate_buffered_admin_response(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    // Do not infer authority from the `/admin/` prefix: retention preview and
    // apply intentionally use that namespace while admitting a workspace
    // owner. Snapshot only a credential that the server-admin admission path
    // accepted, then revalidate that exact credential after the handler has
    // assembled its JSON body.
    let admitted_server_admin = require_admin_with_credential(&state, request.headers()).ok();
    let response = next.run(request).await;
    let Some((actor, source_credential)) = admitted_server_admin else {
        return response;
    };
    if !is_buffered_admin_json_response(&path, &response) {
        return response;
    }

    match ensure_admin_credential_current(&state, &actor, &source_credential) {
        Ok(()) => response,
        // The account-update handler has committed a verified self-disable or
        // self-demotion and deliberately invalidated the caller's former
        // administrative authority. Let only its exact, internal result reach
        // the caller; a later privileged response still needs current admin.
        Err(_)
            if is_self_removal_completion(&state, &path, &response, &actor, &source_credential) =>
        {
            response
        }
        Err(error) => error.into_response(),
    }
}

fn is_buffered_admin_json_response(path: &str, response: &Response) -> bool {
    (path.starts_with("/admin/") || path.starts_with("/debug/"))
        && response.status().is_success()
        && response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"))
}

/// Revalidate an already-admitted administrative actor at a terminal
/// non-HTTP boundary. This keeps filesystem lifecycle operations on the same
/// current-credential and current-admin decision as buffered JSON responses.
pub(crate) fn ensure_admin_credential_current(
    state: &AppState,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    state
        .storage
        .ensure_admin_publication_authorized(actor, source_credential)
}

#[cfg(test)]
mod tests;

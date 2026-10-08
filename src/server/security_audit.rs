use axum::{
    extract::{MatchedPath, Request, State},
    http::Method,
    middleware::Next,
    response::Response,
};

use crate::{
    auth::{opaque_audit_ref, request_audit_identity},
    storage::NewSecurityEvent,
};

use super::{request_client_fingerprint, AppState, ClientRequestMetadata};

mod admission;
pub(super) use admission::SecurityAuditAdmission;
#[cfg(test)]
mod tests;

pub(super) async fn record_request_security_event(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| "/unmatched".to_string());
    let raw_path = request.uri().path().to_string();
    let client_fingerprint = request_client_fingerprint(request.headers()).to_string();
    let metadata = request.extensions().get::<ClientRequestMetadata>().cloned();
    let identity = request_audit_identity(&state, request.headers());

    let response = next.run(request).await;
    let status = response.status();

    if let Some(session_id) = identity
        .as_ref()
        .and_then(|identity| identity.session_id.as_deref())
    {
        if let Err(error) = state.storage.touch_auth_session_client(
            session_id,
            metadata.as_ref().map(|value| value.client_ip.as_str()),
            metadata
                .as_ref()
                .and_then(|value| value.user_agent.as_deref()),
        ) {
            tracing::warn!(%error, "could not refresh session client metadata");
        }
    }

    if !should_record(&route, &method, status.as_u16(), identity.is_some()) {
        return response;
    }
    // No handler or protected resource exists for an unmatched path, so these
    // 4xx scanner probes do not belong in the durable security ledger.
    if route == "/unmatched" {
        return response;
    }
    let category = event_category(&route, &method);
    let actorless_failure = status.as_u16() >= 400
        && identity
            .as_ref()
            .and_then(|identity| identity.actor_email.as_deref())
            .is_none();
    if actorless_failure
        && !state.security_audit_admission.admit_unattributed(
            &route,
            &method,
            status.as_u16(),
            &client_fingerprint,
        )
    {
        return response;
    }
    if category == "guest_access"
        && status.as_u16() < 400
        && !state.admit_low_authority_security_event(&format!(
            "guest\0{route}\0{raw_path}\0{}",
            status.as_u16()
        ))
    {
        return response;
    }

    let low_authority = is_low_authority_interactive_denial(identity.as_ref(), status.as_u16());
    if low_authority {
        let identity = identity.as_ref().expect("classified identity is present");
        if !state.admit_low_authority_security_event(&format!(
            "authenticated-denial\0{}\0{}\0{route}\0{}\0{}",
            identity.credential_kind,
            identity.actor_email.as_deref().unwrap_or("unknown"),
            method.as_str(),
            status.as_u16(),
        )) {
            return response;
        }
    }

    let outcome = event_outcome(status.as_u16());
    let target_ref = route_has_sensitive_target(&route)
        .then(|| opaque_audit_ref(&raw_path, &state.config.token));
    let credential_kind = identity
        .as_ref()
        .map(|value| value.credential_kind)
        .unwrap_or_else(|| {
            if category == "guest_access" {
                "guest"
            } else {
                "anonymous"
            }
        });
    let credential_ref = identity.as_ref().and_then(|value| {
        value
            .delegated_principal_id
            .as_deref()
            .map(|principal_id| opaque_audit_ref(principal_id, &state.config.token))
    });
    let event = NewSecurityEvent {
        category,
        action: method.as_str(),
        route: &route,
        outcome,
        status_code: status.as_u16(),
        actor_email: identity
            .as_ref()
            .and_then(|value| value.actor_email.as_deref()),
        credential_kind,
        credential_ref: credential_ref.as_deref(),
        session_id: identity
            .as_ref()
            .and_then(|value| value.session_id.as_deref()),
        client_ip: metadata.as_ref().map(|value| value.client_ip.as_str()),
        user_agent: metadata
            .as_ref()
            .and_then(|value| value.user_agent.as_deref()),
        target_ref: target_ref.as_deref(),
        low_authority: low_authority || (category == "guest_access" && status.as_u16() < 400),
    };
    if let Err(error) = state.storage.record_security_event(event) {
        tracing::warn!(%error, "could not record security event");
    }
    response
}

fn is_low_authority_interactive_denial(
    identity: Option<&crate::auth::RequestAuditIdentity>,
    status: u16,
) -> bool {
    let Some(identity) = identity else {
        return false;
    };
    (400..=499).contains(&status)
        && identity.actor_email.is_some()
        && !identity.is_admin
        && matches!(
            identity.credential_kind,
            "local_session" | "sso_session" | "delegated_agent_token"
        )
}

fn should_record(route: &str, method: &Method, status: u16, authenticated: bool) -> bool {
    if method == Method::OPTIONS
        || route == "/auth/login"
        || route == "/auth/me"
        || (route == "/admin/security-events" && status < 400)
        || matches!(route, "/health" | "/ready" | "/version" | "/")
        || route.starts_with("/assets/")
    {
        return false;
    }
    if status >= 400 {
        return true;
    }
    if route.starts_with("/pub/") {
        return true;
    }
    if is_content_access_route(route) {
        return true;
    }
    authenticated && !matches!(*method, Method::GET | Method::HEAD)
}

fn event_category(route: &str, method: &Method) -> &'static str {
    if route.starts_with("/pub/") {
        "guest_access"
    } else if is_content_access_route(route) || matches!(*method, Method::GET | Method::HEAD) {
        "access"
    } else {
        "command"
    }
}

fn is_content_access_route(route: &str) -> bool {
    [
        "/content",
        "/download",
        "/preview",
        "/thumbnail",
        "/archive",
    ]
    .iter()
    .any(|part| route.contains(part))
}

fn route_has_sensitive_target(route: &str) -> bool {
    route.contains('{') || route.starts_with("/pub/")
}

fn event_outcome(status: u16) -> &'static str {
    match status {
        200..=399 => "success",
        401 | 403 => "denied",
        423 | 429 => "blocked",
        400..=499 => "rejected",
        _ => "failed",
    }
}

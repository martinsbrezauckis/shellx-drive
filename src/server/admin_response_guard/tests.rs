use super::*;

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::{Duration, Utc};
use serde_json::json;
use tower::ServiceExt;

use crate::{
    auth::{mint_sso_token_with_admin, token_hash, Actor, AuthMode, DriveCredential, ADMIN_ACTOR},
    config::Config,
};

const ADMIN_EMAIL: &str = "terminal-admin@example.test";
const SESSION_ID: &str = "terminal-admin-session";

fn test_state() -> (tempfile::TempDir, AppState, String) {
    let data = tempfile::tempdir().unwrap();
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.path().to_path_buf(),
        token: "terminal-admin-test-token".to_string(),
        bootstrap_token: None,
        e2e_enabled: true,
        email_transport: "capture".to_string(),
        email_from: "ShellX Drive <noreply@example.test>".to_string(),
        public_origin: crate::config::PublicOrigin::parse("http://127.0.0.1").unwrap(),
        email_smtp_host_source: "not_configured".to_string(),
        email_smtp_port: None,
        email_smtp_user_source: "not_configured".to_string(),
        maintenance_token_source: "not_configured".to_string(),
        maintenance_sudo_source: "not_configured".to_string(),
        local_session_ttl_seconds: 2_592_000,
        office_provider_name: "Office editor".to_string(),
        office_provider_url: None,
        office_session_ttl_seconds: 900,
        hosted_mode: false,
        hosted_billing_provider: "none".to_string(),
        hosted_public_rate_limit_per_minute: 60,
        backup_max_archive_bytes: 9 * 1024 * 1024 * 1024 * 1024,
        secure_cookies: false,
        trust_proxy_headers: false,
        update_repo: None,
    };
    let state = AppState::open(config).unwrap();
    let (account, _) = state
        .storage
        .bootstrap_auth_account(ADMIN_EMAIL, "stored-password-hash")
        .unwrap();
    let token = mint_sso_token_with_admin(
        SESSION_ID,
        ADMIN_EMAIL,
        "local-password",
        &account.user_id,
        (Utc::now() + Duration::hours(1)).timestamp(),
        true,
        &state.config.token,
    )
    .unwrap();
    state
        .storage
        .record_auth_session(
            SESSION_ID,
            ADMIN_EMAIL,
            "local-password",
            &account.user_id,
            &token_hash(&token),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    (data, state, token)
}

fn guarded_router(state: AppState, revoke_after_admission: bool) -> Router {
    let terminal_state = state.clone();
    Router::new()
        .route(
            "/debug/terminal-admin-race",
            get(
                move |State(state): State<AppState>, headers: HeaderMap| async move {
                    let (_, _) = require_admin_with_credential(&state, &headers)?;
                    let payload = Json(json!({"sensitive": "selected-before-revocation"}));
                    if revoke_after_admission {
                        state.storage.revoke_auth_session(SESSION_ID, ADMIN_EMAIL)?;
                    }
                    Ok::<_, crate::error::ApiError>(payload)
                },
            ),
        )
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            terminal_state,
            revalidate_buffered_admin_response,
        ))
}

fn self_removal_router(state: AppState, revoke_after_marker: bool) -> Router {
    let operator = Actor {
        email: ADMIN_ACTOR.to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    };
    state
        .storage
        .create_auth_account(
            "remaining-terminal-admin@example.test",
            "remaining-password-hash",
            true,
            &operator,
            &DriveCredential::Operator,
        )
        .unwrap();
    let terminal_state = state.clone();
    Router::new()
        .route(
            "/admin/auth/users/terminal-admin@example.test",
            get(
                move |State(state): State<AppState>, headers: HeaderMap| async move {
                    let (actor, source_credential) =
                        require_admin_with_credential(&state, &headers)?;
                    let version = state
                        .storage
                        .get_auth_account_secret(ADMIN_EMAIL)?
                        .unwrap()
                        .security_version;
                    state.storage.update_auth_account(
                        ADMIN_EMAIL,
                        None,
                        Some(false),
                        None,
                        false,
                        Some(version),
                        &actor,
                        &source_credential,
                    )?;
                    let mut payload = Json(json!({"self_removal_completed": true})).into_response();
                    mark_admin_self_removal_completion(
                        &mut payload,
                        &actor,
                        ADMIN_EMAIL,
                        &source_credential,
                        version + 1,
                        false,
                    );
                    if revoke_after_marker {
                        state.storage.revoke_auth_session(SESSION_ID, ADMIN_EMAIL)?;
                    }
                    Ok::<_, crate::error::ApiError>(payload)
                },
            ),
        )
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            terminal_state,
            revalidate_buffered_admin_response,
        ))
}

fn authorized_request(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn terminal_guard_rejects_a_session_revoked_after_admin_admission() {
    let (_data, state, token) = test_state();
    let response = guarded_router(state, true)
        .oneshot(authorized_request("/debug/terminal-admin-race", &token))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    assert!(!std::str::from_utf8(&body)
        .unwrap()
        .contains("selected-before-revocation"));
}

#[tokio::test]
async fn terminal_guard_keeps_a_live_admin_response_available() {
    let (_data, state, token) = test_state();
    let response = guarded_router(state, false)
        .oneshot(authorized_request("/debug/terminal-admin-race", &token))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    assert!(std::str::from_utf8(&body)
        .unwrap()
        .contains("selected-before-revocation"));
}

#[tokio::test]
async fn self_removal_acknowledgement_requires_the_exact_post_commit_credential_state() {
    let (_data, state, token) = test_state();
    let response = self_removal_router(state, true)
        .oneshot(authorized_request(
            "/admin/auth/users/terminal-admin@example.test",
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    assert!(!std::str::from_utf8(&body)
        .unwrap()
        .contains("self_removal_completed"));
}

#[tokio::test]
async fn self_removal_acknowledgement_is_minimal_after_its_own_role_transition() {
    let (_data, state, token) = test_state();
    let response = self_removal_router(state, false)
        .oneshot(authorized_request(
            "/admin/auth/users/terminal-admin@example.test",
            &token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("self_removal_completed"));
    assert!(!body.contains("account"));
    assert!(!body.contains("receipt"));
}

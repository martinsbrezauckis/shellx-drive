use super::*;

fn identity(kind: &'static str, is_admin: bool) -> crate::auth::RequestAuditIdentity {
    crate::auth::RequestAuditIdentity {
        actor_email: Some("member@example.test".to_string()),
        credential_kind: kind,
        delegated_principal_id: None,
        session_id: Some("session-id".to_string()),
        is_admin,
    }
}

#[test]
fn successful_read_noise_is_not_logged_but_downloads_and_failures_are() {
    assert!(!should_record("/workspaces", &Method::GET, 200, true));
    assert!(!should_record("/auth/me", &Method::GET, 401, false));
    assert!(should_record(
        "/files/{file_id}/download",
        &Method::GET,
        200,
        true
    ));
    assert!(should_record("/workspaces", &Method::GET, 403, true));
    assert!(should_record(
        "/admin/security-events",
        &Method::GET,
        401,
        false
    ));
    assert!(!should_record(
        "/admin/security-events",
        &Method::GET,
        200,
        true
    ));
    assert!(should_record(
        "/pub/shares/{share_id}/files",
        &Method::GET,
        200,
        false
    ));
}

#[test]
fn all_non_admin_interactive_4xx_are_low_authority() {
    let member = identity("local_session", false);
    assert!(is_low_authority_interactive_denial(Some(&member), 403));
    assert!(is_low_authority_interactive_denial(Some(&member), 400));
    assert!(!is_low_authority_interactive_denial(Some(&member), 500));
    assert!(!is_low_authority_interactive_denial(
        Some(&identity("local_session", true)),
        403,
    ));
    assert!(!is_low_authority_interactive_denial(None, 403));
    assert!(is_low_authority_interactive_denial(
        Some(&identity("delegated_agent_token", false)),
        403,
    ));
}

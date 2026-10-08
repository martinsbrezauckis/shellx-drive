use super::*;

#[test]
fn issued_local_bearer_recovers_only_matching_bounded_metadata() {
    let expires = Utc::now() + Duration::hours(1);
    let claims = serde_json::json!({
        "jti": "session-42",
        "email": "person@example.test",
        "issuer": LOCAL_PASSWORD_ISSUER,
        "subject": "local-password",
        "expires_at": expires.timestamp(),
        "admin": false,
    });
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let bearer = format!("sso.v1.{encoded}.opaque-signature");
    let parsed = RemoteSessionRecord::from_local_bearer(
        "https://drive.example.test",
        "Person@Example.Test",
        &bearer,
    )
    .unwrap();
    assert_eq!(parsed.session_id, "session-42");
    assert!(RemoteSessionRecord::from_local_bearer(
        "https://drive.example.test",
        "other@example.test",
        &bearer,
    )
    .is_none());
}

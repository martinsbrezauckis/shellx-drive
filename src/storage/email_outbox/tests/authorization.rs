use chrono::{Duration, Utc};
use rusqlite::params;
use uuid::Uuid;

use crate::{
    auth::{Actor, AuthMode, DriveCredential},
    error::ApiError,
};

use super::storage;

#[test]
fn revoked_admin_session_cannot_capture_queued_delivery_rows() {
    let (_data, storage) = storage();
    let email = "capture-revoked-admin@example.test";
    let (account, _) = storage
        .bootstrap_auth_account(email, "stored-password-hash")
        .unwrap();
    let session_id = Uuid::now_v7().to_string();
    storage
        .record_auth_session(
            &session_id,
            email,
            "local-password",
            &account.user_id,
            "capture-revoked-session-hash",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    storage
        .queue_email("capture-test", email, "subject", "body", None, None)
        .unwrap();
    let actor = Actor {
        email: email.to_string(),
        is_admin: true,
        auth_mode: AuthMode::LocalAccount,
        allowed_workspace_ids: None,
    };
    let credential = DriveCredential::UserSession(session_id.clone());
    storage
        .ensure_admin_publication_authorized(&actor, &credential)
        .unwrap();
    storage.revoke_auth_session(&session_id, email).unwrap();
    assert!(matches!(
        storage.run_email_outbox_capture_authorized(&actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    let queued: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM email_outbox WHERE status = 'queued' AND kind = 'capture-test'",
            params![],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(queued, 1);
}

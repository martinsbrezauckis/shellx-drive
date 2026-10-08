use chrono::{Duration, Utc};
use rusqlite::params;

use super::*;
use crate::{
    auth::{token_hash, Actor},
    storage::{authorization, Storage},
};

#[test]
fn external_parent_kind_never_falls_back_after_binding_loss_or_rebinding() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "external-parent@example.test";
    storage
        .bootstrap_auth_account(email, "stored-password-hash")
        .unwrap();
    let parent_hash = token_hash("parent-session-token");
    storage
        .record_auth_session(
            "external-parent-session",
            email,
            "oidc-test",
            "external-subject",
            &parent_hash,
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let delegated_hash = token_hash("sxd_agent_external-parent");
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO agent_principals (
                     id, name, created_by, creator_authority_kind, delegation_parent_kind,
                     disabled_at, created_at, publication_pending
                 ) VALUES ('external-principal', 'External', ?1, 'user', 'external_sso',
                           NULL, ?2, 0)",
            params![email, Utc::now().to_rfc3339()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agent_tokens (
                     id, principal_id, token_hash, delegation_kind, expires_at, last_used_at,
                     revoked_at, created_at, publication_pending
                 ) VALUES ('external-token', 'external-principal', ?1, 'delegated', ?2, NULL,
                           NULL, ?3, 0)",
            params![
                &delegated_hash,
                (Utc::now() + Duration::minutes(30)).to_rfc3339(),
                Utc::now().to_rfc3339(),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO delegated_agent_parent_sessions (
                     principal_id, parent_session_id, owner_email, issuer, subject,
                     parent_token_hash, created_at
                 ) VALUES ('external-principal', 'external-parent-session', ?1, 'oidc-test',
                           'external-subject', ?2, ?3)",
            params![email, &parent_hash, Utc::now().to_rfc3339()],
        )
        .unwrap();
    }
    assert!(storage
        .authenticate_delegated_agent_token(&delegated_hash, Utc::now().timestamp())
        .unwrap()
        .is_some());
    let archived_tables = storage.export_backup_tables().unwrap();
    let sso_actor = Actor {
        email: email.to_string(),
        is_admin: false,
        auth_mode: AuthMode::Sso,
        allowed_workspace_ids: None,
    };
    let staged_hash = token_hash("sxd_agent_pending-external-parent");
    let pending = storage
        .create_pending_delegated_agent(
            "Pending external",
            &staged_hash,
            &(Utc::now() + Duration::minutes(30)).to_rfc3339(),
            &sso_actor,
            &DriveCredential::UserSession("external-parent-session".to_string()),
        )
        .unwrap();

    let conn = storage.conn.lock().unwrap();
    conn.execute(
        "UPDATE auth_sessions SET token_hash = 'rebound-token-hash'
             WHERE id = 'external-parent-session'",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(matches!(
        storage.publish_pending_delegated_agent(
            &pending,
            &sso_actor,
            &DriveCredential::UserSession("external-parent-session".to_string()),
        ),
        Err(ApiError::Unauthenticated)
    ));
    assert!(storage
        .authenticate_delegated_agent_token(&staged_hash, Utc::now().timestamp())
        .unwrap()
        .is_none());
    assert!(matches!(
        storage.authenticate_delegated_agent_token(&delegated_hash, Utc::now().timestamp()),
        Err(ApiError::Unauthenticated)
    ));

    let conn = storage.conn.lock().unwrap();
    conn.execute(
        "UPDATE auth_sessions SET token_hash = ?1, subject = 'rebound-subject'
             WHERE id = 'external-parent-session'",
        [&parent_hash],
    )
    .unwrap();
    drop(conn);
    assert!(matches!(
        storage.authenticate_delegated_agent_token(&delegated_hash, Utc::now().timestamp()),
        Err(ApiError::Unauthenticated)
    ));

    let conn = storage.conn.lock().unwrap();
    conn.execute(
        "UPDATE auth_sessions SET token_hash = ?1, subject = 'external-subject'
             WHERE id = 'external-parent-session'",
        [&parent_hash],
    )
    .unwrap();
    drop(conn);
    storage.restore_backup_tables(&archived_tables).unwrap();
    let restored_kind: String = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT delegation_parent_kind FROM agent_principals WHERE id = 'external-principal'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(restored_kind, "external_sso");
    assert!(storage
        .authenticate_delegated_agent_token(&delegated_hash, Utc::now().timestamp())
        .unwrap()
        .is_none());
    let actor = Actor {
        email: email.to_string(),
        is_admin: false,
        auth_mode: AuthMode::DelegatedAgent,
        allowed_workspace_ids: None,
    };
    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    assert!(matches!(
        authorization::ensure_source_credential_active(
            &tx,
            &actor,
            &DriveCredential::DelegatedAgentToken("external-token".to_string()),
        ),
        Err(ApiError::Unauthenticated)
    ));
}

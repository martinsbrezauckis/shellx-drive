use chrono::{Duration, Utc};
use rusqlite::params;

use crate::{
    auth::{token_hash, DriveCredential},
    error::ApiError,
    model::{AgentPermission, CreateFileRequest, FileKind},
    storage::Storage,
};

use super::common::test_source;

#[test]
fn staged_agent_access_is_unusable_until_live_publication() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential, workspace_id, root) =
        test_source(&storage, "pending-agent-publication@example.test");
    let plaintext = "sxd_agent_pending-publication";
    let pending = storage
        .create_pending_agent_access_publication(
            "Pending worker",
            &workspace_id,
            &root.id,
            AgentPermission::View,
            &token_hash(plaintext),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();

    assert!(storage
        .authenticate_agent_token(&token_hash(plaintext), Utc::now().timestamp())
        .unwrap()
        .is_none());
    storage
        .publish_pending_agent_access(&pending, &actor, &credential)
        .unwrap();
    let authenticated = storage
        .authenticate_agent_token(&token_hash(plaintext), Utc::now().timestamp())
        .unwrap()
        .unwrap();
    assert_eq!(authenticated.principal_id, pending.access.principal_id);
    let (grants, _) = storage
        .list_active_agent_access_for_principal(
            &authenticated.principal_id,
            &authenticated.token_id,
            None,
            25,
        )
        .unwrap();
    storage
        .ensure_agent_session_publication_authorized(
            &authenticated.principal_id,
            &authenticated.token_id,
            &grants,
        )
        .unwrap();
}

#[test]
fn denied_agent_access_publication_retires_all_staged_rows() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential, workspace_id, root) =
        test_source(&storage, "revoked-agent-publication@example.test");
    let pending = storage
        .create_pending_agent_access_publication(
            "Revoked worker",
            &workspace_id,
            &root.id,
            AgentPermission::View,
            &token_hash("sxd_agent_revoked-publication"),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    let DriveCredential::UserSession(session_id) = &credential else {
        unreachable!();
    };
    storage
        .revoke_auth_session(session_id, &actor.email)
        .unwrap();
    assert!(matches!(
        storage.publish_pending_agent_access(&pending, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    let retired: (
        i64,
        Option<String>,
        i64,
        Option<String>,
        i64,
        Option<String>,
    ) = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT p.publication_pending, p.disabled_at,
                    t.publication_pending, t.revoked_at,
                    g.publication_pending, g.revoked_at
             FROM agent_principals p
             JOIN agent_tokens t ON t.principal_id = p.id
             JOIN agent_folder_grants g ON g.principal_id = p.id
             WHERE p.id = ?1 AND t.id = ?2 AND g.id = ?3",
            params![
                &pending.access.principal_id,
                &pending.access.token_id,
                &pending.access.grant_id,
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(retired.0, 1);
    assert!(retired.1.is_some());
    assert_eq!(retired.2, 1);
    assert!(retired.3.is_some());
    assert_eq!(retired.4, 1);
    assert!(retired.5.is_some());
}

#[test]
fn pending_grant_is_retired_when_the_agent_token_is_revoked_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential, workspace_id, root) =
        test_source(&storage, "grant-subject-publication@example.test");
    let (access, _) = storage
        .create_agent_access(
            "Grant subject worker",
            &workspace_id,
            &root.id,
            AgentPermission::View,
            &token_hash("sxd_agent_grant-subject"),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    let second_root = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.clone(),
                parent_id: None,
                name: "Second agent root".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0;
    let pending = storage
        .grant_pending_agent_access_publication(
            &access.principal_id,
            &workspace_id,
            &second_root.id,
            AgentPermission::View,
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE agent_tokens SET revoked_at = ?2 WHERE id = ?1",
            params![&access.token_id, Utc::now().to_rfc3339()],
        )
        .unwrap();

    assert!(matches!(
        storage.publish_pending_agent_access(&pending, &actor, &credential),
        Err(ApiError::Forbidden)
    ));
    let retired: (i64, Option<String>) = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT publication_pending, revoked_at FROM agent_folder_grants WHERE id = ?1",
            [&pending.access.grant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retired.0, 1);
    assert!(retired.1.is_some());
    assert!(storage
        .get_agent_access(&pending.access.grant_id)
        .unwrap()
        .is_none());
}

#[test]
fn concurrent_staged_replacements_leave_only_the_last_published_grant_active() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential, workspace_id, root) =
        test_source(&storage, "concurrent-grant-publication@example.test");
    let (initial, _) = storage
        .create_agent_access(
            "Concurrent grant worker",
            &workspace_id,
            &root.id,
            AgentPermission::View,
            &token_hash("sxd_agent_concurrent-grants"),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    let stage = |permission| {
        storage
            .grant_pending_agent_access_publication(
                &initial.principal_id,
                &workspace_id,
                &root.id,
                permission,
                &(Utc::now() + Duration::hours(1)).to_rfc3339(),
                &actor,
                &credential,
            )
            .unwrap()
    };
    let first = stage(AgentPermission::View);
    let second = stage(AgentPermission::Edit);
    assert_ne!(first.access.grant_id, second.access.grant_id);

    storage
        .publish_pending_agent_access(&first, &actor, &credential)
        .unwrap();
    storage
        .publish_pending_agent_access(&second, &actor, &credential)
        .unwrap();

    let conn = storage.conn.lock().unwrap();
    let active: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_folder_grants
             WHERE principal_id = ?1 AND root_file_id = ?2
               AND publication_pending = 0 AND revoked_at IS NULL",
            params![&initial.principal_id, &root.id],
            |row| row.get(0),
        )
        .unwrap();
    let first_revoked: Option<String> = conn
        .query_row(
            "SELECT revoked_at FROM agent_folder_grants WHERE id = ?1",
            [&first.access.grant_id],
            |row| row.get(0),
        )
        .unwrap();
    let second_revoked: Option<String> = conn
        .query_row(
            "SELECT revoked_at FROM agent_folder_grants WHERE id = ?1",
            [&second.access.grant_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active, 1);
    assert!(first_revoked.is_some());
    assert!(second_revoked.is_none());
}

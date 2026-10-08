use chrono::{Duration, Utc};
use rusqlite::params;

use crate::{
    auth::{Actor, AuthMode, DriveCredential, WorkspaceRole},
    model::{CreateFileRequest, FileKind},
    storage::{auth_sessions::retention::MAX_ACTIVE_AUTH_SESSIONS_PER_ACTOR, Storage},
};

fn grant_editor(storage: &Storage, workspace_id: &str, email: &str) {
    let operator = Actor {
        email: "system@local".to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    };
    storage
        .upsert_workspace_member(
            workspace_id,
            email,
            WorkspaceRole::Editor,
            &operator,
            &DriveCredential::Operator,
        )
        .unwrap();
}

#[test]
fn issuance_retires_the_oldest_actor_session_and_its_office_derivative() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Session retention", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "office.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let actor = "editor@example.test";
    grant_editor(&storage, &workspace.id, actor);
    let first_session_id = "retention-session-0";
    storage
        .record_auth_session(
            first_session_id,
            actor,
            "oidc-test",
            "editor-subject",
            "retention-token-0",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let (_, office_token) = storage
        .create_office_edit_session(
            &file.id,
            actor,
            &DriveCredential::UserSession(first_session_id.to_string()),
            file.revision,
            "Office editor",
            900,
        )
        .unwrap();
    assert!(storage
        .get_office_edit_session_by_token(&office_token)
        .unwrap()
        .is_some());

    for index in 1..=MAX_ACTIVE_AUTH_SESSIONS_PER_ACTOR {
        storage
            .record_auth_session(
                &format!("retention-session-{index}"),
                actor,
                "oidc-test",
                "editor-subject",
                &format!("retention-token-{index}"),
                &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            )
            .unwrap();
    }

    let sessions = storage.list_auth_sessions().unwrap();
    assert!(sessions
        .iter()
        .find(|session| session.id == first_session_id)
        .is_some_and(|session| session.revoked));
    assert_eq!(
        storage
            .list_active_auth_sessions_for_actor(actor)
            .unwrap()
            .len(),
        MAX_ACTIVE_AUTH_SESSIONS_PER_ACTOR
    );
    assert!(storage
        .get_office_edit_session_by_token(&office_token)
        .unwrap()
        .is_none());
}

#[test]
fn issuance_prunes_old_expired_and_revoked_history() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let now = Utc::now();
    let conn = storage.conn.lock().unwrap();
    for (id, expires_at, revoked_at) in [
        (
            "old-expired-session",
            (now - Duration::days(8)).to_rfc3339(),
            None,
        ),
        (
            "old-revoked-session",
            (now + Duration::days(1)).to_rfc3339(),
            Some((now - Duration::days(31)).to_rfc3339()),
        ),
    ] {
        conn.execute(
            "INSERT INTO auth_sessions (
                 id, actor_email, issuer, subject, token_hash,
                 expires_at, revoked_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                "retention@example.test",
                "oidc-test",
                "retention-subject",
                format!("{id}-hash"),
                expires_at,
                revoked_at,
                (now - Duration::days(32)).to_rfc3339(),
            ],
        )
        .unwrap();
    }
    drop(conn);

    storage
        .record_auth_session(
            "new-session",
            "retention@example.test",
            "oidc-test",
            "retention-subject",
            "new-session-hash",
            &(now + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();

    let sessions = storage.list_auth_sessions().unwrap();
    assert!(sessions
        .iter()
        .all(|session| session.id != "old-expired-session"));
    assert!(sessions
        .iter()
        .all(|session| session.id != "old-revoked-session"));
}

#[test]
fn actor_session_revocation_preserves_operator_office_sessions() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Credential scope", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "office.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let actor = "editor@example.test";
    grant_editor(&storage, &workspace.id, actor);
    let session_id = "revoke-all-session";
    storage
        .record_auth_session(
            session_id,
            actor,
            "oidc-test",
            "editor-subject",
            "revoke-all-token",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    let (_, session_office_token) = storage
        .create_office_edit_session(
            &file.id,
            actor,
            &DriveCredential::UserSession(session_id.to_string()),
            file.revision,
            "Office editor",
            900,
        )
        .unwrap();
    let (_, operator_office_token) = storage
        .create_office_edit_session(
            &file.id,
            actor,
            &DriveCredential::Operator,
            file.revision,
            "Office editor",
            900,
        )
        .unwrap();
    assert!(storage
        .get_office_edit_session_by_token(&session_office_token)
        .unwrap()
        .is_some());
    assert!(storage
        .get_office_edit_session_by_token(&operator_office_token)
        .unwrap()
        .is_some());

    assert_eq!(storage.revoke_auth_sessions_for_actor(actor).unwrap(), 1);
    assert!(storage
        .get_office_edit_session_by_token(&session_office_token)
        .unwrap()
        .is_none());
    assert!(storage
        .get_office_edit_session_by_token(&operator_office_token)
        .unwrap()
        .is_some());
}

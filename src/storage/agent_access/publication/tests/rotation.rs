use chrono::{Duration, Utc};

use crate::{auth::token_hash, error::ApiError, model::AgentPermission, storage::Storage};

use super::common::test_source;

#[test]
fn rotation_keeps_the_old_agent_token_live_until_publication() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential, workspace_id, root) =
        test_source(&storage, "rotation-agent-publication@example.test");
    let old_plaintext = "sxd_agent_live-before-rotation";
    let (access, _) = storage
        .create_agent_access(
            "Rotation worker",
            &workspace_id,
            &root.id,
            AgentPermission::View,
            &token_hash(old_plaintext),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    let new_plaintext = "sxd_agent_pending-rotation";
    let pending = storage
        .stage_pending_agent_principal_rotation(
            &access.principal_id,
            &token_hash(new_plaintext),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    assert!(storage
        .authenticate_agent_token(&token_hash(old_plaintext), Utc::now().timestamp())
        .unwrap()
        .is_some());
    assert!(storage
        .authenticate_agent_token(&token_hash(new_plaintext), Utc::now().timestamp())
        .unwrap()
        .is_none());
    storage
        .publish_pending_agent_principal_rotation(&pending, &actor, &credential)
        .unwrap();
    assert!(storage
        .authenticate_agent_token(&token_hash(old_plaintext), Utc::now().timestamp())
        .unwrap()
        .is_none());
    assert!(storage
        .authenticate_agent_token(&token_hash(new_plaintext), Utc::now().timestamp())
        .unwrap()
        .is_some());
}

#[test]
fn agent_session_terminal_recheck_rejects_every_revoked_subject() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential, workspace_id, root) =
        test_source(&storage, "terminal-agent-publication@example.test");
    let plaintext = "sxd_agent_terminal-recheck";
    let (access, _) = storage
        .create_agent_access(
            "Terminal worker",
            &workspace_id,
            &root.id,
            AgentPermission::View,
            &token_hash(plaintext),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            &actor,
            &credential,
        )
        .unwrap();
    let authenticated = storage
        .authenticate_agent_token(&token_hash(plaintext), Utc::now().timestamp())
        .unwrap()
        .unwrap();
    let (selected_grants, _) = storage
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
            &selected_grants,
        )
        .unwrap();

    for statement in [
        "UPDATE agent_tokens SET revoked_at = '2026-08-30T00:00:00Z' WHERE id = ?1",
        "UPDATE agent_principals SET disabled_at = '2026-08-30T00:00:00Z' WHERE id = ?1",
        "UPDATE agent_folder_grants SET revoked_at = '2026-08-30T00:00:00Z' WHERE id = ?1",
    ] {
        let target = if statement.contains("agent_tokens") {
            &access.token_id
        } else if statement.contains("agent_principals") {
            &access.principal_id
        } else {
            &access.grant_id
        };
        storage
            .conn
            .lock()
            .unwrap()
            .execute(statement, [target])
            .unwrap();
        assert!(matches!(
            storage.ensure_agent_session_publication_authorized(
                &authenticated.principal_id,
                &authenticated.token_id,
                &selected_grants,
            ),
            Err(ApiError::Forbidden)
        ));
        let reset = if statement.contains("agent_tokens") {
            "UPDATE agent_tokens SET revoked_at = NULL WHERE id = ?1"
        } else if statement.contains("agent_principals") {
            "UPDATE agent_principals SET disabled_at = NULL WHERE id = ?1"
        } else {
            "UPDATE agent_folder_grants SET revoked_at = NULL WHERE id = ?1"
        };
        storage
            .conn
            .lock()
            .unwrap()
            .execute(reset, [target])
            .unwrap();
    }
    let conn = storage.conn.lock().unwrap();
    conn.execute(
        "UPDATE agent_principals SET creator_authority_kind = 'legacy_ambiguous' WHERE id = ?1",
        [&access.principal_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE agent_folder_grants
         SET creator_authority_kind = 'legacy_ambiguous' WHERE id = ?1",
        [&access.grant_id],
    )
    .unwrap();
    drop(conn);
    assert!(matches!(
        storage.ensure_agent_session_publication_authorized(
            &authenticated.principal_id,
            &authenticated.token_id,
            &selected_grants,
        ),
        Err(ApiError::Forbidden)
    ));
}

use super::*;

#[test]
fn migration_reuses_existing_owner_workspace_and_is_idempotent() {
    let (_directory, storage, workspace_id) = storage();
    let file = create(&storage, &workspace_id, None, "existing", FileKind::File);
    storage
        .conn
        .lock()
        .unwrap()
        .execute("DELETE FROM account_private_workspaces", [])
        .unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let mapped: String = conn.query_row(
        "SELECT private.workspace_id FROM account_private_workspaces private JOIN auth_accounts accounts ON accounts.user_id = private.user_id WHERE accounts.email = ?1",
        [OWNER], |row| row.get(0),
    ).unwrap();
    assert_eq!(mapped, workspace_id);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM files WHERE id = ?1", [&file], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
    drop(conn);
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let mappings: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM account_private_workspaces",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(mappings, 2);
}

#[test]
fn migration_assigns_a_multi_owner_workspace_to_one_deterministic_private_owner() {
    let (_directory, storage, owner_private) = storage();
    let recipient_account = storage.get_auth_account(RECIPIENT).unwrap().unwrap();
    let recipient_private = format!("private-v1:{}", recipient_account.user_id);
    let (shared, _, _) = storage
        .create_workspace("Historical shared", OWNER)
        .unwrap();
    let recipient_id = recipient_account.user_id;
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?1, ?2, 'owner')",
            [&shared.id, &recipient_id],
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE workspaces SET archived_at = '2026-01-01T00:00:00Z' WHERE id IN (?1, ?2)",
            [&owner_private, &recipient_private],
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute("DELETE FROM account_private_workspaces", [])
        .unwrap();
    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let owner_mapping: String = conn.query_row(
        "SELECT private.workspace_id FROM account_private_workspaces private JOIN auth_accounts accounts ON accounts.user_id = private.user_id WHERE accounts.email = ?1",
        [OWNER], |row| row.get(0),
    ).unwrap();
    let recipient_mapping: String = conn.query_row(
        "SELECT private.workspace_id FROM account_private_workspaces private JOIN auth_accounts accounts ON accounts.user_id = private.user_id WHERE accounts.email = ?1",
        [RECIPIENT], |row| row.get(0),
    ).unwrap();
    assert_eq!(owner_mapping, shared.id);
    assert_eq!(recipient_mapping, recipient_private);
    let recipient_still_member: i64 = conn.query_row(
        "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = ?1 AND user_id = ?2 AND role = 'owner'",
        [&shared.id, &recipient_id], |row| row.get(0),
    ).unwrap();
    assert_eq!(recipient_still_member, 1);
}

#[test]
fn migration_defaults_everyone_policy_to_disabled_without_revoking_existing_grants() {
    let (_directory, storage, workspace_id) = storage();
    storage
        .update_everyone_grant_policy_authorized(
            crate::model::UpdateEveryoneGrantPolicyRequest {
                everyone_grants_enabled: true,
            },
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let file = create(
        &storage,
        &workspace_id,
        None,
        "legacy everyone",
        FileKind::File,
    );
    let (grant, _) = storage
        .create_human_item_grant(
            &file,
            &human_grant("everyone", None, "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM server_settings WHERE key = 'human_item_grants.everyone_enabled'",
            [],
        )
        .unwrap();

    storage.migrate().unwrap();

    assert!(
        !storage
            .everyone_grant_policy()
            .unwrap()
            .everyone_grants_enabled
    );
    assert_eq!(
        storage.list_human_item_grants(&file).unwrap()[0].id,
        grant.id
    );
    assert!(storage
        .ensure_item_permission(&file, &human(RECIPIENT), WorkspacePermission::Read)
        .is_ok());
    assert!(matches!(
        storage.update_human_item_grant(
            &grant.id,
            Some("editor"),
            None,
            &operator(),
            &DriveCredential::Operator,
        ),
        Err(ApiError::Validation(_))
    ));
    storage
        .revoke_human_item_grant(&grant.id, &operator(), &DriveCredential::Operator)
        .unwrap();
}

use super::*;

fn assert_last_owner_error<T>(result: ApiResult<T>) {
    assert!(matches!(
        result,
        Err(ApiError::Validation(message)) if message.contains("last workspace owner")
    ));
}

#[test]
fn expired_legacy_owner_never_satisfies_any_last_owner_guard() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Expired owner guard", "owner@example.test")
        .unwrap();
    let (operator, operator_credential) = test_operator();
    storage
        .upsert_workspace_member(
            &workspace.id,
            "expired@example.test",
            WorkspaceRole::Owner,
            &operator,
            &operator_credential,
        )
        .unwrap();
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE workspace_members SET expires_at = ?1
             WHERE workspace_id = ?2 AND user_id = (
                 SELECT id FROM users WHERE email = ?3
             )",
            params![
                (Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
                &workspace.id,
                "expired@example.test"
            ],
        )
        .unwrap();

    assert_last_owner_error(storage.upsert_workspace_member(
        &workspace.id,
        "owner@example.test",
        WorkspaceRole::Editor,
        &operator,
        &operator_credential,
    ));
    storage
        .create_workspace_invitation(
            &workspace.id,
            "owner@example.test",
            WorkspaceRole::Viewer,
            None,
            "expired-owner-invitation-token",
            "Invitation",
            &operator,
            &operator_credential,
        )
        .unwrap();
    let (owner, owner_credential, _) = test_local_account_session(&storage, "owner@example.test");
    assert_last_owner_error(storage.accept_workspace_invitation_for_account(
        "expired-owner-invitation-token",
        "owner@example.test",
        &owner,
        &owner_credential,
    ));
    assert_last_owner_error(storage.remove_workspace_member(
        &workspace.id,
        "owner@example.test",
        &operator,
        &operator_credential,
    ));
    assert_last_owner_error(storage.leave_workspace(&workspace.id, &owner, &owner_credential));

    let owner = storage
        .workspace_member_by_email(&workspace.id, "owner@example.test")
        .unwrap()
        .unwrap();
    assert_eq!(owner.role, "owner");
}

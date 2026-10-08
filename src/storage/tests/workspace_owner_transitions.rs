use super::*;

#[test]
fn member_upsert_cannot_demote_the_last_workspace_owner() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Owner guard", "owner@example.test")
        .unwrap();
    let (operator, credential) = test_operator();

    assert!(matches!(storage.upsert_workspace_member(
        &workspace.id, "owner@example.test", WorkspaceRole::Editor, &operator, &credential,
    ), Err(ApiError::Validation(message)) if message.contains("last workspace owner")));
    assert_eq!(
        storage
            .workspace_member_by_email(&workspace.id, "owner@example.test",)
            .unwrap()
            .unwrap()
            .role,
        "owner"
    );

    storage
        .upsert_workspace_member(
            &workspace.id,
            "replacement@example.test",
            WorkspaceRole::Owner,
            &operator,
            &credential,
        )
        .unwrap();
    let (demoted, _) = storage
        .upsert_workspace_member(
            &workspace.id,
            "owner@example.test",
            WorkspaceRole::Editor,
            &operator,
            &credential,
        )
        .unwrap();
    assert_eq!(demoted.role, "editor");
}

#[test]
fn invitation_acceptance_cannot_demote_the_last_workspace_owner() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Invitation owner guard", "owner@example.test")
        .unwrap();
    let (operator, credential) = test_operator();
    storage
        .create_workspace_invitation(
            &workspace.id,
            "owner@example.test",
            WorkspaceRole::Viewer,
            None,
            "owner-demotion-invitation-token",
            "Invitation",
            &operator,
            &credential,
        )
        .unwrap();
    let (owner, owner_credential, _) = test_local_account_session(&storage, "owner@example.test");

    assert!(matches!(storage.accept_workspace_invitation_for_account(
        "owner-demotion-invitation-token", "owner@example.test", &owner, &owner_credential,
    ), Err(ApiError::Validation(message)) if message.contains("last workspace owner")));
    assert_eq!(
        storage
            .workspace_member_by_email(&workspace.id, "owner@example.test",)
            .unwrap()
            .unwrap()
            .role,
        "owner"
    );
    assert_eq!(
        storage.list_workspace_invitations(&workspace.id).unwrap()[0].status,
        "pending"
    );

    storage
        .upsert_workspace_member(
            &workspace.id,
            "replacement@example.test",
            WorkspaceRole::Owner,
            &operator,
            &credential,
        )
        .unwrap();
    let (_, demoted, _) = storage
        .accept_workspace_invitation_for_account(
            "owner-demotion-invitation-token",
            "owner@example.test",
            &owner,
            &owner_credential,
        )
        .unwrap();
    assert_eq!(demoted.role, "viewer");
}

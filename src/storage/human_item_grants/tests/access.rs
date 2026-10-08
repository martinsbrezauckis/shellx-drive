use super::*;

#[test]
fn grants_are_scoped_inherited_and_revocable() {
    let (_directory, storage, workspace_id) = storage();
    let shared_folder = create(&storage, &workspace_id, None, "Shared", FileKind::Folder);
    let child = create(
        &storage,
        &workspace_id,
        Some(&shared_folder),
        "child",
        FileKind::File,
    );
    let sibling = create(&storage, &workspace_id, None, "Private", FileKind::File);
    let (_grant, _) = storage
        .create_human_item_grant(
            &shared_folder,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let recipient = human(RECIPIENT);
    let inherited = storage
        .ensure_item_permission(&child, &recipient, WorkspacePermission::Read)
        .unwrap();
    assert!(inherited.inherited);
    assert_eq!(inherited.role, "viewer");
    assert!(matches!(
        storage.ensure_item_permission(&child, &recipient, WorkspacePermission::Write),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage.ensure_item_permission(&sibling, &recipient, WorkspacePermission::Read),
        Err(ApiError::Forbidden)
    ));

    let roots = storage.list_sync_roots_for_actor(&recipient).unwrap();
    let root = roots
        .iter()
        .find(|root| root.root_file_id.as_deref() == Some(&shared_folder))
        .unwrap();
    assert_eq!(root.kind, "item_grant");
    assert!(root.access_generation > 0);
    let (_root, files, _) = storage
        .sync_root_manifest(&root.id, &recipient, root.access_generation)
        .unwrap();
    assert_eq!(
        files
            .iter()
            .map(|file| file.id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([shared_folder.as_str(), child.as_str()])
    );

    let grant_id = root.grant_id.clone().unwrap();
    storage
        .revoke_human_item_grant(&grant_id, &operator(), &DriveCredential::Operator)
        .unwrap();
    assert!(matches!(
        storage.ensure_item_permission(&child, &recipient, WorkspacePermission::Read),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn manifest_publication_rejects_a_generation_raced_after_enumeration() {
    let (_directory, storage, workspace_id) = storage();
    let shared = create(&storage, &workspace_id, None, "Shared", FileKind::Folder);
    let (grant, _) = storage
        .create_human_item_grant(
            &shared,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (recipient, credential) = session_for_existing_account(&storage, RECIPIENT);
    let root = storage
        .list_sync_roots_for_actor(&recipient)
        .unwrap()
        .into_iter()
        .find(|root| root.grant_id.as_deref() == Some(grant.id.as_str()))
        .unwrap();
    let (_root, files, _) = storage
        .sync_root_manifest(&root.id, &recipient, root.access_generation)
        .unwrap();

    storage
        .update_human_item_grant(
            &grant.id,
            Some("editor"),
            None,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    assert!(matches!(
        storage.ensure_sync_root_manifest_publication_authorized(
            &root.id,
            &files,
            &recipient,
            &credential,
            root.access_generation,
        ),
        Err(ApiError::PreconditionFailed)
    ));

    let current = storage
        .list_sync_roots_for_actor(&recipient)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.id == root.id)
        .unwrap();
    assert!(current.access_generation > root.access_generation);
    let (_root, files, _) = storage
        .sync_root_manifest(&current.id, &recipient, current.access_generation)
        .unwrap();
    assert!(storage
        .ensure_sync_root_manifest_publication_authorized(
            &current.id,
            &files,
            &recipient,
            &credential,
            current.access_generation,
        )
        .is_ok());
}

#[test]
fn scoped_roles_gate_mutations_and_webdav_before_workspace_listing() {
    let (_directory, storage, workspace_id) = storage();
    let shared_folder = create(&storage, &workspace_id, None, "Shared", FileKind::Folder);
    let child = create(
        &storage,
        &workspace_id,
        Some(&shared_folder),
        "child",
        FileKind::File,
    );
    let sibling = create(&storage, &workspace_id, None, "sentinel", FileKind::File);
    let (grant, _) = storage
        .create_human_item_grant(
            &shared_folder,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (recipient, credential) = session_for_existing_account(&storage, RECIPIENT);
    storage
        .create_notification(
            RECIPIENT,
            "item_shared",
            "Shared item",
            "The sibling must never appear here.",
            Some(&workspace_id),
            Some(&child),
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        storage
            .list_notifications_visible_to_actor(&recipient, false)
            .unwrap()
            .len(),
        1
    );

    assert!(matches!(
        storage.ensure_whole_workspace_permission(
            &workspace_id,
            &recipient,
            WorkspacePermission::Read,
        ),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage.ensure_item_permission(&sibling, &recipient, WorkspacePermission::Read),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage.put_content_authorized(&child, 1, &"a".repeat(64), 1, &recipient, &credential),
        Err(ApiError::Forbidden)
    ));

    storage
        .update_human_item_grant(
            &grant.id,
            Some("editor"),
            None,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    storage
        .put_content_authorized(&child, 1, &"b".repeat(64), 1, &recipient, &credential)
        .unwrap();
    assert!(matches!(
        storage.update_file_authorized(
            &child,
            UpdateFileRequest {
                base_revision: Some(2),
                name: None,
                parent_id: None,
                move_to_root: Some(true),
                collision_policy: None,
                replace_target_id: None,
                replace_target_revision: None,
                labels: None,
                custom_metadata: None,
            },
            &recipient,
            &credential,
        ),
        Err(ApiError::Forbidden)
    ));

    storage
        .revoke_human_item_grant(&grant.id, &operator(), &DriveCredential::Operator)
        .unwrap();
    assert!(storage
        .list_notifications_visible_to_actor(&recipient, false)
        .unwrap()
        .is_empty());
    assert!(matches!(
        storage.ensure_item_publication_authorized(
            &child,
            &recipient,
            &credential,
            WorkspacePermission::Read,
        ),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn editor_group_everyone_expiry_and_move_are_resolved_live() {
    let (_directory, storage, workspace_id) = storage();
    let shared_folder = create(&storage, &workspace_id, None, "Shared", FileKind::Folder);
    let child = create(
        &storage,
        &workspace_id,
        Some(&shared_folder),
        "child",
        FileKind::File,
    );
    let (grant, _) = storage
        .create_human_item_grant(
            &shared_folder,
            &human_grant("account", Some(RECIPIENT), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    storage
        .update_human_item_grant(
            &grant.id,
            Some("editor"),
            None,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let recipient = human(RECIPIENT);
    assert_eq!(
        storage
            .ensure_item_permission(&child, &recipient, WorkspacePermission::Write)
            .unwrap()
            .role,
        "editor"
    );

    let (group, _) = storage
        .create_group_authorized("Reviewers", &operator(), &DriveCredential::Operator)
        .unwrap();
    storage
        .upsert_group_member_authorized(
            &group.id,
            RECIPIENT,
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let group_file = create(&storage, &workspace_id, None, "Group", FileKind::File);
    storage
        .create_human_item_grant(
            &group_file,
            &human_grant("group", Some(&group.id), "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    assert!(storage
        .ensure_item_permission(&group_file, &recipient, WorkspacePermission::Read)
        .is_ok());

    let everyone_file = create(&storage, &workspace_id, None, "Everyone", FileKind::File);
    storage
        .update_everyone_grant_policy_authorized(
            crate::model::UpdateEveryoneGrantPolicyRequest {
                everyone_grants_enabled: true,
            },
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (everyone, _) = storage
        .create_human_item_grant(
            &everyone_file,
            &human_grant("everyone", None, "viewer"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    assert!(storage
        .ensure_item_permission(&everyone_file, &recipient, WorkspacePermission::Read)
        .is_ok());
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE human_item_grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            [&everyone.id],
        )
        .unwrap();
    let generation_before: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT generation FROM human_item_access_generation WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(matches!(
        storage.ensure_item_permission(&everyone_file, &recipient, WorkspacePermission::Read),
        Err(ApiError::Forbidden)
    ));
    let generation_after: i64 = storage
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT generation FROM human_item_access_generation WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(generation_after > generation_before);

    storage
        .update_file(
            &child,
            UpdateFileRequest {
                base_revision: None,
                name: None,
                parent_id: None,
                move_to_root: Some(true),
                collision_policy: None,
                replace_target_id: None,
                replace_target_revision: None,
                labels: None,
                custom_metadata: None,
            },
        )
        .unwrap();
    assert!(matches!(
        storage.ensure_item_permission(&child, &recipient, WorkspacePermission::Read),
        Err(ApiError::Forbidden)
    ));
}

mod upload_destinations;

#[path = "access/expiry.rs"]
mod expiry;

use super::*;

fn create_node(
    storage: &Storage,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
    kind: FileKind,
) -> DriveFile {
    storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id: parent_id.map(str::to_string),
                name: name.to_string(),
                kind,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0
}

fn move_request(
    parent_id: Option<&str>,
    name: &str,
    collision_policy: Option<&str>,
) -> UpdateFileRequest {
    UpdateFileRequest {
        base_revision: Some(1),
        name: Some(name.to_string()),
        parent_id: parent_id.map(str::to_string),
        move_to_root: parent_id.is_none().then_some(true),
        collision_policy: collision_policy.map(str::to_string),
        replace_target_id: None,
        replace_target_revision: None,
        labels: None,
        custom_metadata: None,
    }
}

#[test]
fn move_collision_policy_keeps_both_and_cancels_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Collisions", "owner@example.test")
        .unwrap();
    let source_parent = create_node(&storage, &workspace.id, None, "source", FileKind::Folder);
    let destination = create_node(
        &storage,
        &workspace.id,
        None,
        "destination",
        FileKind::Folder,
    );
    let nested_source = create_node(
        &storage,
        &workspace.id,
        Some(&source_parent.id),
        "source.txt",
        FileKind::File,
    );
    let _nested_collision = create_node(
        &storage,
        &workspace.id,
        Some(&destination.id),
        "occupied.txt",
        FileKind::File,
    );
    create_node(
        &storage,
        &workspace.id,
        None,
        "root-occupied.txt",
        FileKind::File,
    );

    let root_cancel_source = create_node(
        &storage,
        &workspace.id,
        Some(&source_parent.id),
        "root-cancel.txt",
        FileKind::File,
    );
    let root_keep_source = create_node(
        &storage,
        &workspace.id,
        Some(&source_parent.id),
        "root-keep.txt",
        FileKind::File,
    );

    let nested = storage
        .update_file(
            &nested_source.id,
            move_request(Some(&destination.id), "occupied.txt", None),
        )
        .unwrap()
        .0;
    assert_eq!(nested.parent_id.as_deref(), Some(destination.id.as_str()));
    assert_eq!(nested.name, "occupied (copy).txt");
    assert!(matches!(
        storage.update_file(
            &root_cancel_source.id,
            move_request(None, "root-occupied.txt", Some("cancel")),
        ),
        Err(ApiError::Conflict)
    ));
    let unchanged = storage.get_file(&root_cancel_source.id).unwrap().unwrap();
    assert_eq!(
        unchanged.parent_id.as_deref(),
        Some(source_parent.id.as_str())
    );
    assert_eq!(unchanged.name, "root-cancel.txt");
    assert_eq!(unchanged.revision, 1);

    let root = storage
        .update_file(
            &root_keep_source.id,
            move_request(None, "root-occupied.txt", None),
        )
        .unwrap()
        .0;
    assert_eq!(root.parent_id, None);
    assert_eq!(root.name, "root-occupied (copy).txt");
}

#[test]
fn exact_destination_copy_rejects_an_occupant_added_after_path_preflight() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("WebDAV copy admission", "owner@example.test")
        .unwrap();
    let source = create_node(&storage, &workspace.id, None, "source.txt", FileKind::File);

    // WebDAV observed this missing path before awaiting its blob lifecycle
    // lock; another transport can commit the requested name next.
    assert!(storage
        .get_child_file_by_name(&workspace.id, None, "destination.txt")
        .unwrap()
        .is_none());
    create_node(
        &storage,
        &workspace.id,
        None,
        "destination.txt",
        FileKind::File,
    );

    let (actor, credential) = test_operator();
    assert!(matches!(
        storage.copy_file_authorized_exact_destination(
            &source.id,
            "destination.txt".to_string(),
            CopyParentId::Root,
            &actor,
            &credential,
        ),
        Err(ApiError::Conflict)
    ));
    assert!(storage
        .get_child_file_by_name(&workspace.id, None, "destination (copy).txt")
        .unwrap()
        .is_none());
    assert!(!storage.get_file(&source.id).unwrap().unwrap().trashed);
}

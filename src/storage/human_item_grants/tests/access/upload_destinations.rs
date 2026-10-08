use super::*;
use crate::storage::{NewUploadCompletion, UploadAdmissionPolicy, UploadSessionCreate};

#[test]
fn upload_completion_rechecks_the_resolved_destination_after_a_move() {
    let (_directory, storage, workspace_id) = storage();
    let shared = create(&storage, &workspace_id, None, "Shared", FileKind::Folder);
    let nested = create(
        &storage,
        &workspace_id,
        Some(&shared),
        "Nested",
        FileKind::Folder,
    );
    storage
        .create_human_item_grant(
            &shared,
            &human_grant("account", Some(RECIPIENT), "editor"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (recipient, credential) = session_for_existing_account(&storage, RECIPIENT);

    let start = |name: &str| {
        storage
            .create_upload_session_authorized(
                UploadSessionCreate {
                    workspace_id: &workspace_id,
                    actor_email: RECIPIENT,
                    parent_id: Some(shared.clone()),
                    name,
                    total_size: Some(3),
                    path: Some(format!("Nested/{name}")),
                    duplicate_policy: "keep_both",
                },
                UploadAdmissionPolicy::default(),
                &recipient,
                &credential,
            )
            .unwrap()
    };

    let allowed = start("allowed.bin");
    let (allowed_parent, allowed_name) = storage
        .resolve_relative_upload_path_authorized(
            &workspace_id,
            Some(&shared),
            "Nested/allowed.bin",
            &recipient,
            &credential,
        )
        .unwrap();
    let completed = storage
        .complete_new_upload_session(NewUploadCompletion {
            upload_id: &allowed.id,
            actor: &recipient,
            source_credential: &credential,
            received_bytes: 3,
            parent_id: allowed_parent,
            name: allowed_name,
            content_hash: "allowed-hash",
        })
        .unwrap();
    assert_eq!(completed.file.parent_id.as_deref(), Some(nested.as_str()));

    let raced = start("raced.bin");
    let (raced_parent, raced_name) = storage
        .resolve_relative_upload_path_authorized(
            &workspace_id,
            Some(&shared),
            "Nested/raced.bin",
            &recipient,
            &credential,
        )
        .unwrap();
    assert_eq!(raced_parent.as_deref(), Some(nested.as_str()));
    storage
        .update_file(
            &nested,
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
    let files_before = storage.list_files().unwrap().len();
    assert!(matches!(
        storage.complete_new_upload_session(NewUploadCompletion {
            upload_id: &raced.id,
            actor: &recipient,
            source_credential: &credential,
            received_bytes: 3,
            parent_id: raced_parent,
            name: raced_name,
            content_hash: "raced-hash",
        }),
        Err(ApiError::NotFound)
    ));
    assert_eq!(storage.list_files().unwrap().len(), files_before);
    assert!(
        !storage
            .get_upload_session(&raced.id)
            .unwrap()
            .unwrap()
            .completed
    );

    let root_attempt = start("root.bin");
    assert!(matches!(
        storage.complete_new_upload_session(NewUploadCompletion {
            upload_id: &root_attempt.id,
            actor: &recipient,
            source_credential: &credential,
            received_bytes: 3,
            parent_id: None,
            name: "root.bin".to_string(),
            content_hash: "root-hash",
        }),
        Err(ApiError::Forbidden)
    ));
    assert_eq!(storage.list_files().unwrap().len(), files_before);
}

#[test]
fn stale_replacement_cannot_create_a_sibling_outside_a_file_grant() {
    let (_directory, storage, workspace_id) = storage();
    let target = create(&storage, &workspace_id, None, "Target", FileKind::File);
    storage
        .create_human_item_grant(
            &target,
            &human_grant("account", Some(RECIPIENT), "editor"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (recipient, credential) = session_for_existing_account(&storage, RECIPIENT);
    let start = || {
        storage
            .create_replacement_upload_session_authorized(
                &target,
                1,
                &recipient,
                &credential,
                3,
                UploadAdmissionPolicy::default(),
            )
            .unwrap()
    };
    let winner = start();
    let stale = start();
    let replaced = storage
        .complete_replacement_upload_session(&winner.id, &recipient, &credential, 3, "winner-hash")
        .unwrap();
    assert_eq!(replaced.file.id, target);
    assert_eq!(replaced.file.revision, 2);

    let files_before = storage.list_files().unwrap().len();
    assert!(matches!(
        storage.complete_replacement_upload_session(
            &stale.id,
            &recipient,
            &credential,
            3,
            "stale-hash",
        ),
        Err(ApiError::Forbidden)
    ));
    assert_eq!(storage.list_files().unwrap().len(), files_before);
    assert!(
        !storage
            .get_upload_session(&stale.id)
            .unwrap()
            .unwrap()
            .completed
    );
}

#[test]
fn stale_content_write_cannot_create_a_sibling_outside_a_file_grant() {
    let (_directory, storage, workspace_id) = storage();
    let target = create(&storage, &workspace_id, None, "Target", FileKind::File);
    storage
        .create_human_item_grant(
            &target,
            &human_grant("account", Some(RECIPIENT), "editor"),
            &operator(),
            &DriveCredential::Operator,
        )
        .unwrap();
    let (recipient, credential) = session_for_existing_account(&storage, RECIPIENT);
    storage
        .put_content_authorized(&target, 1, &"a".repeat(64), 3, &recipient, &credential)
        .unwrap();
    let files_before = storage.list_files().unwrap().len();
    assert!(matches!(
        storage.put_content_authorized(&target, 1, &"b".repeat(64), 3, &recipient, &credential,),
        Err(ApiError::Forbidden)
    ));
    assert_eq!(storage.list_files().unwrap().len(), files_before);

    let (owner, owner_credential) = session_for_existing_account(&storage, OWNER);
    assert!(matches!(
        storage.put_content_authorized(&target, 1, &"c".repeat(64), 3, &owner, &owner_credential,),
        Ok(crate::model::ContentWrite::Conflict(_))
    ));
    assert_eq!(storage.list_files().unwrap().len(), files_before + 1);
}

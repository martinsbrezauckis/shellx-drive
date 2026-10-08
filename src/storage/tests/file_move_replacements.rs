use crate::{
    model::{CreateFileRequest, CreateHumanItemGrantRequest, FileKind, UpdateFileRequest},
    storage::Storage,
};

use super::test_operator;

fn create_node(
    storage: &Storage,
    workspace_id: &str,
    name: &str,
    kind: FileKind,
) -> crate::model::DriveFile {
    storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id: None,
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

fn create_file(storage: &Storage, workspace_id: &str, name: &str) -> crate::model::DriveFile {
    create_node(storage, workspace_id, name, FileKind::File)
}

fn replace_request(
    source_revision: i64,
    target_id: &str,
    target_revision: i64,
) -> UpdateFileRequest {
    UpdateFileRequest {
        base_revision: Some(source_revision),
        name: Some("report.txt".to_string()),
        parent_id: None,
        move_to_root: Some(true),
        collision_policy: Some("replace".to_string()),
        replace_target_id: Some(target_id.to_string()),
        replace_target_revision: Some(target_revision),
        labels: None,
        custom_metadata: None,
    }
}

fn grant(recipient: &str) -> CreateHumanItemGrantRequest {
    CreateHumanItemGrantRequest {
        principal_kind: "account".to_string(),
        principal_ref: Some(recipient.to_string()),
        role: "viewer".to_string(),
        expires_at: None,
    }
}

#[test]
fn replace_keeps_the_destination_id_history_and_grants() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Replace history", "owner@example.test")
        .unwrap();
    let source = create_file(&storage, &workspace.id, "incoming.txt");
    let target = create_file(&storage, &workspace.id, "report.txt");
    storage
        .put_content(&source.id, 1, "source-body", 11)
        .unwrap();
    storage
        .put_content(&target.id, 1, "target-body", 11)
        .unwrap();
    let (_, _, _) = storage
        .update_file(
            &source.id,
            UpdateFileRequest {
                base_revision: Some(2),
                name: None,
                parent_id: None,
                move_to_root: None,
                collision_policy: None,
                replace_target_id: None,
                replace_target_revision: None,
                labels: Some(vec!["incoming".to_string()]),
                custom_metadata: Some(serde_json::json!({"origin": "source"})),
            },
        )
        .unwrap();
    let (operator, credential) = test_operator();
    storage
        .bootstrap_auth_account("replacement-owner@example.test", "hash")
        .unwrap();
    for recipient in ["source-grant@example.test", "target-grant@example.test"] {
        storage
            .create_auth_account(recipient, "hash", false, &operator, &credential)
            .unwrap();
    }
    let (source_grant, _) = storage
        .create_human_item_grant(
            &source.id,
            &grant("source-grant@example.test"),
            &operator,
            &credential,
        )
        .unwrap();
    let (target_grant, _) = storage
        .create_human_item_grant(
            &target.id,
            &grant("target-grant@example.test"),
            &operator,
            &credential,
        )
        .unwrap();

    let (replaced, metadata, _) = storage
        .update_file(&source.id, replace_request(3, &target.id, 2))
        .unwrap();

    assert_eq!(replaced.id, target.id);
    assert_eq!(replaced.name, "report.txt");
    assert_eq!(replaced.revision, 3);
    assert_eq!(replaced.content_hash.as_deref(), Some("source-body"));
    assert_eq!(metadata.labels, vec!["incoming"]);
    assert_eq!(metadata.custom_metadata["origin"], "source");
    let retained_source = storage.get_file(&source.id).unwrap().unwrap();
    assert!(retained_source.trashed);
    assert_eq!(retained_source.revision, 4);
    assert_eq!(
        storage
            .file_revision_content_hash(&target.id, 2)
            .unwrap()
            .as_deref(),
        Some("target-body")
    );
    assert_eq!(
        storage
            .file_revision_content_hash(&target.id, 3)
            .unwrap()
            .as_deref(),
        Some("source-body")
    );
    assert_eq!(storage.list_file_revisions(&target.id).unwrap().len(), 3);
    assert_eq!(
        storage.list_human_item_grants(&source.id).unwrap()[0].id,
        source_grant.id
    );
    assert_eq!(
        storage.list_human_item_grants(&target.id).unwrap()[0].id,
        target_grant.id
    );
}

#[test]
fn replace_rolls_back_when_the_canonical_target_write_fails() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Replace rollback", "owner@example.test")
        .unwrap();
    let source = create_file(&storage, &workspace.id, "incoming.txt");
    let target = create_file(&storage, &workspace.id, "report.txt");
    let receipts = storage.list_receipts().unwrap().len();
    let conn = storage.conn.lock().unwrap();
    conn.execute_batch(&format!(
        "CREATE TRIGGER reject_replace BEFORE UPDATE OF content_hash ON files
         WHEN NEW.id = '{}' BEGIN SELECT RAISE(ABORT, 'replace rejected'); END;",
        target.id
    ))
    .unwrap();
    drop(conn);

    assert!(matches!(
        storage.update_file(&source.id, replace_request(1, "different-target", 1)),
        Err(crate::error::ApiError::Conflict)
    ));
    assert!(matches!(
        storage.update_file(&source.id, replace_request(1, &target.id, 99)),
        Err(crate::error::ApiError::Conflict)
    ));
    assert!(!storage.get_file(&source.id).unwrap().unwrap().trashed);
    assert!(!storage.get_file(&target.id).unwrap().unwrap().trashed);

    assert!(storage
        .update_file(&source.id, replace_request(1, &target.id, 1))
        .is_err());
    let unchanged_source = storage.get_file(&source.id).unwrap().unwrap();
    let unchanged_target = storage.get_file(&target.id).unwrap().unwrap();
    assert!(!unchanged_source.trashed);
    assert_eq!(unchanged_source.revision, 1);
    assert!(!unchanged_target.trashed);
    assert_eq!(unchanged_target.revision, 1);
    assert_eq!(storage.list_receipts().unwrap().len(), receipts);
}

#[test]
fn replace_rejects_a_folder_destination_without_trashing_either_item() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Replace folder", "owner@example.test")
        .unwrap();
    let source = create_file(&storage, &workspace.id, "incoming.txt");
    let folder = create_node(&storage, &workspace.id, "report.txt", FileKind::Folder);

    assert!(matches!(
        storage.update_file(&source.id, replace_request(1, &folder.id, 1)),
        Err(crate::error::ApiError::Validation(_))
    ));
    assert!(!storage.get_file(&source.id).unwrap().unwrap().trashed);
    assert!(!storage.get_file(&folder.id).unwrap().unwrap().trashed);
}

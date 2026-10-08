use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::{
    auth::{Actor, AuthMode, DriveCredential, WorkspaceRole},
    error::ApiError,
    model::{CreateFileRequest, CreateFolderTemplateItemRequest, DriveFile, FileKind},
    storage::PreparedFolderTemplateItem,
};

use super::*;

fn local_session(storage: &Storage, email: &str) -> (Actor, DriveCredential) {
    storage
        .bootstrap_auth_account(email, "stored-password-hash")
        .unwrap();
    let account = storage.get_auth_account_secret(email).unwrap().unwrap();
    let session_id = Uuid::now_v7().to_string();
    storage
        .record_auth_session(
            &session_id,
            email,
            "local-password",
            &account.user_id,
            &format!("session-hash-{session_id}"),
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
        )
        .unwrap();
    (
        Actor {
            email: email.to_string(),
            is_admin: false,
            auth_mode: AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        },
        DriveCredential::UserSession(session_id),
    )
}

fn operator() -> (Actor, DriveCredential) {
    (
        Actor {
            email: "system@local".to_string(),
            is_admin: true,
            auth_mode: AuthMode::Operator,
            allowed_workspace_ids: None,
        },
        DriveCredential::Operator,
    )
}

fn file_with_prior_revision(storage: &Storage, workspace_id: &str) -> DriveFile {
    let (file, _) = storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id: None,
                name: "history.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some("a".repeat(64)),
            1,
        )
        .unwrap();
    storage
        .put_content(&file.id, 1, &"b".repeat(64), 1)
        .unwrap();
    storage.get_file(&file.id).unwrap().unwrap()
}

fn prepared_template_items() -> Vec<PreparedFolderTemplateItem> {
    vec![PreparedFolderTemplateItem {
        path: "Docs".to_string(),
        kind: FileKind::Folder,
        content_hash: None,
        content_bytes: 0,
        content_text: None,
    }]
}

fn template_items() -> Vec<CreateFolderTemplateItemRequest> {
    vec![CreateFolderTemplateItemRequest {
        path: "Docs".to_string(),
        kind: FileKind::Folder,
        content: None,
    }]
}

#[test]
fn protocol_mutations_recheck_a_revoked_source_session_before_commit() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential) = local_session(&storage, "owner@example.test");
    let (workspace, _, _) = storage
        .create_workspace("Protocol revocation", &actor.email)
        .unwrap();
    let file = file_with_prior_revision(&storage, &workspace.id);
    let (template, _) = storage
        .create_folder_template_authorized(
            &workspace.id,
            "Project kit",
            None,
            template_items(),
            &actor,
            &credential,
        )
        .unwrap();
    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage
        .revoke_auth_session(session_id, &actor.email)
        .unwrap();

    assert!(matches!(
        storage.put_content_authorized(
            &file.id,
            file.revision,
            &"c".repeat(64),
            1,
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.create_folder_template_authorized(
            &workspace.id,
            "Blocked kit",
            None,
            template_items(),
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.apply_folder_template_authorized(
            &workspace.id,
            &template.id,
            "Blocked root",
            prepared_template_items(),
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage
            .delete_folder_template_authorized(&workspace.id, &template.id, &actor, &credential,),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.restore_file_revision_authorized(&file.id, 1, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.set_revision_pinned_authorized(&file.id, 1, true, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.delete_file_revision_authorized(&file.id, 1, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));
    assert!(matches!(
        storage.prune_file_revisions_authorized(&file.id, &actor, &credential),
        Err(ApiError::Unauthenticated)
    ));

    assert_eq!(storage.get_file(&file.id).unwrap().unwrap().revision, 2);
    assert!(storage.get_folder_template(&template.id).unwrap().is_some());
    assert!(storage
        .list_file_revisions(&file.id)
        .unwrap()
        .iter()
        .all(|revision| !revision.pinned));
}

#[test]
fn protocol_mutations_recheck_current_workspace_role_before_commit() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (actor, credential) = local_session(&storage, "owner@example.test");
    let (workspace, _, _) = storage
        .create_workspace("Protocol demotion", &actor.email)
        .unwrap();
    let file = file_with_prior_revision(&storage, &workspace.id);
    let (template, _) = storage
        .create_folder_template_authorized(
            &workspace.id,
            "Project kit",
            None,
            template_items(),
            &actor,
            &credential,
        )
        .unwrap();
    let (operator, operator_credential) = operator();
    storage
        .upsert_workspace_member(
            &workspace.id,
            "coowner@example.test",
            WorkspaceRole::Owner,
            &operator,
            &operator_credential,
        )
        .unwrap();
    storage
        .upsert_workspace_member(
            &workspace.id,
            &actor.email,
            WorkspaceRole::Editor,
            &operator,
            &operator_credential,
        )
        .unwrap();

    assert!(matches!(
        storage.set_revision_pinned_authorized(&file.id, 1, true, &actor, &credential),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage.prune_file_revisions_authorized(&file.id, &actor, &credential),
        Err(ApiError::Forbidden)
    ));

    storage
        .upsert_workspace_member(
            &workspace.id,
            &actor.email,
            WorkspaceRole::Viewer,
            &operator,
            &operator_credential,
        )
        .unwrap();

    assert!(matches!(
        storage.put_content_authorized(
            &file.id,
            file.revision,
            &"c".repeat(64),
            1,
            &actor,
            &credential,
        ),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage.create_folder_template_authorized(
            &workspace.id,
            "Blocked kit",
            None,
            template_items(),
            &actor,
            &credential,
        ),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage.apply_folder_template_authorized(
            &workspace.id,
            &template.id,
            "Blocked root",
            prepared_template_items(),
            &actor,
            &credential,
        ),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage
            .delete_folder_template_authorized(&workspace.id, &template.id, &actor, &credential,),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage.restore_file_revision_authorized(&file.id, 1, &actor, &credential),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        storage.delete_file_revision_authorized(&file.id, 1, &actor, &credential),
        Err(ApiError::Forbidden)
    ));

    assert_eq!(storage.get_file(&file.id).unwrap().unwrap().revision, 2);
    assert!(storage.get_folder_template(&template.id).unwrap().is_some());
    assert!(storage
        .list_file_revisions(&file.id)
        .unwrap()
        .iter()
        .all(|revision| !revision.pinned));
}

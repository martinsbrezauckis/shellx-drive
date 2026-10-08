use super::*;
use crate::model::{CreateFileRequest, FileKind};

#[test]
fn terminal_derived_publication_revalidates_credentials_and_attached_hashes() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let email = "terminal-derived-reader@example.test";
    let (actor, credential, _) = test_local_account_session(&storage, email);
    let (workspace, _, _) = storage
        .create_workspace("Terminal derived publication", email)
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "private.png".to_string(),
                kind: FileKind::File,
                content: Some("private".to_string()),
                path: None,
            },
            Some("a".repeat(64)),
        )
        .unwrap();
    let thumbnail_hash = "b".repeat(64);
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO file_previews (
                file_id, workspace_id, revision, kind, content,
                thumbnail_hash, thumbnail_content_type, thumbnail_bytes,
                width, height, status, updated_at
             ) VALUES (?1, ?2, ?3, 'image_thumbnail', '', ?4, 'image/png', 1,
                       1, 1, 'ready', ?5)",
            params![
                &file.id,
                &workspace.id,
                file.revision,
                &thumbnail_hash,
                Utc::now().to_rfc3339()
            ],
        )
        .unwrap();
    storage
        .ensure_thumbnail_publication_authorized(
            &workspace.id,
            &file.id,
            file.revision,
            &thumbnail_hash,
            &actor,
            &credential,
        )
        .unwrap();

    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE file_previews SET thumbnail_hash = ?2 WHERE file_id = ?1",
            params![&file.id, "c".repeat(64)],
        )
        .unwrap();
    assert!(matches!(
        storage.ensure_thumbnail_publication_authorized(
            &workspace.id,
            &file.id,
            file.revision,
            &thumbnail_hash,
            &actor,
            &credential,
        ),
        Err(ApiError::NotFound)
    ));

    let (folder, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "Covered".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let cover_hash = "d".repeat(64);
    storage
        .set_folder_cover(&folder.id, &cover_hash, 1)
        .unwrap();
    storage
        .ensure_cover_publication_authorized(
            &workspace.id,
            &folder.id,
            &cover_hash,
            &actor,
            &credential,
        )
        .unwrap();
    storage
        .set_folder_cover(&folder.id, &"e".repeat(64), 1)
        .unwrap();
    assert!(matches!(
        storage.ensure_cover_publication_authorized(
            &workspace.id,
            &folder.id,
            &cover_hash,
            &actor,
            &credential,
        ),
        Err(ApiError::NotFound)
    ));

    let session_id = match &credential {
        DriveCredential::UserSession(id) => id,
        _ => unreachable!(),
    };
    storage.revoke_auth_session(session_id, email).unwrap();
    assert!(matches!(
        storage.ensure_cover_publication_authorized(
            &workspace.id,
            &folder.id,
            &"e".repeat(64),
            &actor,
            &credential,
        ),
        Err(ApiError::Unauthenticated)
    ));
}

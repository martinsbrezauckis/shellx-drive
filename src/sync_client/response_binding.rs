use anyhow::{bail, ensure};

use crate::model::{DriveFile, FileKind, UploadSession};

use super::validate_remote_cache_id;

pub(super) fn validate_new_upload_session(
    session: &UploadSession,
    workspace_id: &str,
    name: &str,
    total_size: u64,
) -> anyhow::Result<()> {
    validate_session_common(session, workspace_id, total_size)?;
    ensure!(
        session.parent_id.is_none()
            && session.name == name
            && session.path.is_none()
            && session.target_file_id.is_none()
            && session.base_revision.is_none(),
        "new upload session response did not match the requested destination"
    );
    Ok(())
}

pub(super) fn validate_replacement_upload_session(
    session: &UploadSession,
    workspace_id: &str,
    file_id: &str,
    base_revision: i64,
    total_size: u64,
) -> anyhow::Result<()> {
    validate_session_common(session, workspace_id, total_size)?;
    ensure!(
        session.target_file_id.as_deref() == Some(file_id)
            && session.base_revision == Some(base_revision),
        "replacement upload session response did not match the requested file revision"
    );
    Ok(())
}

pub(super) fn validate_created_file(
    file: &DriveFile,
    workspace_id: &str,
    name: &str,
    content_hash: &str,
    size: u64,
) -> anyhow::Result<()> {
    let expected_size = i64::try_from(size)
        .map_err(|_| anyhow::anyhow!("created file size exceeded the protocol range"))?;
    validate_remote_cache_id("file", &file.id)?;
    ensure!(
        file.workspace_id == workspace_id
            && file.parent_id.is_none()
            && file.name == name
            && matches!(&file.kind, FileKind::File)
            && file.revision == 1
            && !file.trashed
            && file.content_hash.as_deref() == Some(content_hash)
            && file.size_bytes == Some(expected_size),
        "remote create response did not match the requested file"
    );
    Ok(())
}

pub(super) fn validate_updated_file(
    file: &DriveFile,
    workspace_id: &str,
    file_id: &str,
    base_revision: i64,
    content_hash: &str,
    size: u64,
) -> anyhow::Result<()> {
    let expected_size = i64::try_from(size)
        .map_err(|_| anyhow::anyhow!("updated file size exceeded the protocol range"))?;
    ensure!(
        file.id == file_id
            && file.workspace_id == workspace_id
            && matches!(&file.kind, FileKind::File)
            && base_revision.checked_add(1) == Some(file.revision)
            && !file.trashed
            && file.content_hash.as_deref() == Some(content_hash)
            && file.size_bytes == Some(expected_size),
        "remote update response did not match the requested file revision"
    );
    Ok(())
}

pub(super) fn validate_chunk_session_id(actual_id: &str, expected_id: &str) -> anyhow::Result<()> {
    if actual_id != expected_id {
        bail!("upload chunk response belonged to a different upload session");
    }
    Ok(())
}

fn validate_session_common(
    session: &UploadSession,
    workspace_id: &str,
    total_size: u64,
) -> anyhow::Result<()> {
    validate_remote_cache_id("upload session", &session.id)?;
    ensure!(
        session.workspace_id == workspace_id
            && session.total_size == i64::try_from(total_size).ok()
            && session.received_bytes == 0
            && !session.completed
            && !session.canceled
            && session.file_id.is_none()
            && session.upload_url == format!("/uploads/resumable/{}", session.id),
        "upload session response did not match the requested transfer"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> DriveFile {
        DriveFile {
            id: "018f3a4e-8a1a-7c23-8f8d-9a1b2c3d4e5f".to_string(),
            workspace_id: "018f3a4e-8a1a-7c23-8f8d-9a1b2c3d4e60".to_string(),
            parent_id: None,
            name: "safe.txt".to_string(),
            kind: FileKind::File,
            revision: 2,
            trashed: false,
            starred: false,
            content_hash: Some("hash".to_string()),
            created_at: "2026-08-27T00:00:00Z".to_string(),
            updated_at: "2026-08-27T00:00:00Z".to_string(),
            size_bytes: Some(4),
            folder_size_bytes: None,
            has_cover: false,
        }
    }

    fn session() -> UploadSession {
        let id = "018f3a4e-8a1a-7c23-8f8d-9a1b2c3d4e63".to_string();
        UploadSession {
            upload_url: format!("/uploads/resumable/{id}"),
            id,
            workspace_id: "018f3a4e-8a1a-7c23-8f8d-9a1b2c3d4e60".to_string(),
            actor_email: "owner@example.test".to_string(),
            parent_id: None,
            name: "safe.txt".to_string(),
            total_size: Some(4),
            received_bytes: 0,
            completed: false,
            canceled: false,
            file_id: None,
            created_at: "2026-08-27T00:00:00Z".to_string(),
            updated_at: "2026-08-27T00:00:00Z".to_string(),
            canceled_at: None,
            path: None,
            duplicate_policy: "keep_both".to_string(),
            target_file_id: None,
            base_revision: None,
            completion_receipt_id: None,
            completion_current_revision: None,
        }
    }

    #[test]
    fn update_binding_rejects_cross_workspace_or_cross_file_responses() {
        let expected_workspace = file().workspace_id;
        let expected_id = file().id;
        let mut response = file();
        assert!(
            validate_updated_file(&response, &expected_workspace, &expected_id, 1, "hash", 4)
                .is_ok()
        );

        response.workspace_id = "018f3a4e-8a1a-7c23-8f8d-9a1b2c3d4e61".to_string();
        assert!(
            validate_updated_file(&response, &expected_workspace, &expected_id, 1, "hash", 4)
                .is_err()
        );
        response.workspace_id = expected_workspace.clone();
        response.id = "018f3a4e-8a1a-7c23-8f8d-9a1b2c3d4e62".to_string();
        assert!(
            validate_updated_file(&response, &expected_workspace, &expected_id, 1, "hash", 4)
                .is_err()
        );
    }

    #[test]
    fn new_session_binding_rejects_destination_substitution() {
        let expected_workspace = session().workspace_id;
        let mut response = session();
        assert!(validate_new_upload_session(&response, &expected_workspace, "safe.txt", 4).is_ok());

        response.name = "other.txt".to_string();
        assert!(
            validate_new_upload_session(&response, &expected_workspace, "safe.txt", 4).is_err()
        );
        response.name = "safe.txt".to_string();
        response.workspace_id = "018f3a4e-8a1a-7c23-8f8d-9a1b2c3d4e64".to_string();
        assert!(
            validate_new_upload_session(&response, &expected_workspace, "safe.txt", 4).is_err()
        );
    }

    #[test]
    fn replacement_session_and_chunk_binding_reject_substitution() {
        let expected_workspace = session().workspace_id;
        let target = "018f3a4e-8a1a-7c23-8f8d-9a1b2c3d4e5f";
        let mut response = session();
        response.target_file_id = Some(target.to_string());
        response.base_revision = Some(1);
        assert!(
            validate_replacement_upload_session(&response, &expected_workspace, target, 1, 4)
                .is_ok()
        );

        response.base_revision = Some(2);
        assert!(
            validate_replacement_upload_session(&response, &expected_workspace, target, 1, 4)
                .is_err()
        );
        assert!(validate_chunk_session_id(&response.id, &response.id).is_ok());
        assert!(validate_chunk_session_id(&response.id, target).is_err());
    }
}

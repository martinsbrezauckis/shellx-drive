use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind, MobileFileMetadata},
};

pub(super) fn mobile_file_metadata(
    file: DriveFile,
    workspace_storage_mode: &str,
    offline_ids: &std::collections::HashSet<String>,
) -> MobileFileMetadata {
    let has_content = file.content_hash.is_some();
    let kind = file.kind.clone();
    let downloadable = workspace_storage_mode == "open"
        && matches!(kind, FileKind::File)
        && !file.trashed
        && has_content;
    MobileFileMetadata {
        id: file.id.clone(),
        workspace_id: file.workspace_id,
        parent_id: file.parent_id,
        name: file.name,
        kind: file.kind,
        revision: file.revision,
        trashed: file.trashed,
        starred: file.starred,
        has_content,
        downloadable,
        offline_marked: offline_ids.contains(&file.id),
        created_at: file.created_at,
        updated_at: file.updated_at,
    }
}

pub(super) fn ensure_mobile_downloadable(file: &DriveFile, storage_mode: &str) -> ApiResult<()> {
    let _ = storage_mode;
    if matches!(&file.kind, FileKind::File) && !file.trashed && file.content_hash.is_some() {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "file is not downloadable for mobile offline".to_string(),
        ))
    }
}

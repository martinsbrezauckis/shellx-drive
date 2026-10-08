use crate::{
    blob,
    error::{ApiError, ApiResult},
    model::{CreateFileRequest, DriveFile, FileKind, TwinScenarioRunResponse},
    server::AppState,
};

use super::assertion;

pub(super) const BROWSE_SCALE_ROUNDTRIP: &str = "browse_scale_roundtrip";
pub(super) const TRASH_NESTED_BEFORE_ASSERTIONS: &str = "trash_nested_before_assertions";

pub(super) fn run_browse_scale_roundtrip(
    state: AppState,
    faults: Vec<String>,
) -> ApiResult<TwinScenarioRunResponse> {
    let (workspace, _, _) = state
        .storage
        .create_workspace("Twin Browse Workspace", "twin@example.test")?;
    let root = create_node(&state, &workspace.id, None, "root", FileKind::Folder, b"")?;
    let nested = create_node(
        &state,
        &workspace.id,
        Some(&root.id),
        "nested",
        FileKind::Folder,
        b"",
    )?;
    let direct = create_node(
        &state,
        &workspace.id,
        Some(&root.id),
        "direct.bin",
        FileKind::File,
        b"abc",
    )?;
    let nested_file = create_node(
        &state,
        &workspace.id,
        Some(&nested.id),
        "nested.bin",
        FileKind::File,
        b"12345",
    )?;

    if faults
        .iter()
        .any(|fault| fault == TRASH_NESTED_BEFORE_ASSERTIONS)
    {
        state.storage.set_trashed(&nested_file.id, true)?;
    }

    let files = state.storage.list_files_for_workspace(&workspace.id)?;
    let current_root = find(&files, &root.id)?;
    let current_nested = find(&files, &nested.id)?;
    let current_direct = find(&files, &direct.id)?;
    let (browse_workspaces, large_folders) = state.storage.debug_browse_aggregates()?;
    let browse_workspace = browse_workspaces
        .iter()
        .find(|row| row.workspace_id == workspace.id)
        .ok_or(ApiError::NotFound)?;
    let root_large_folder = large_folders
        .iter()
        .find(|row| row.workspace_id == workspace.id && row.direct_children == 2);
    let assertions = vec![
        assertion(
            "recursive_root_size",
            current_root.folder_size_bytes == Some(8),
            "root folder reports all current descendant bytes",
            "root folder size changed after the injected nested trash",
        ),
        assertion(
            "recursive_nested_size",
            current_nested.folder_size_bytes == Some(5),
            "nested folder reports its current descendant bytes",
            "nested folder size changed after the injected nested trash",
        ),
        assertion(
            "file_size_contract",
            current_direct.size_bytes == Some(3) && current_direct.folder_size_bytes.is_none(),
            "files expose body bytes without a folder aggregate",
            "file and folder size fields are inconsistent",
        ),
        assertion(
            "browse_direct_child_summary",
            browse_workspace.max_direct_children == 2,
            "browse diagnostics report the largest direct-child count",
            "browse diagnostics returned the wrong direct-child count",
        ),
        assertion(
            "browse_large_folder_is_bounded_and_sized",
            root_large_folder.is_some_and(|row| row.folder_size_bytes == 8)
                && large_folders.len() <= 50,
            "bounded browse diagnostics include the sized root folder",
            "bounded browse diagnostics reflect the injected size change",
        ),
    ];
    let passed = assertions.iter().all(|assertion| assertion.passed);
    let receipt = state
        .storage
        .insert_receipt("twin.run", "system", Some(&workspace.id))?;
    Ok(TwinScenarioRunResponse {
        scenario: BROWSE_SCALE_ROUNDTRIP.to_string(),
        faults,
        passed,
        workspace_id: workspace.id,
        file_id: root.id,
        assertions,
        receipt,
    })
}

fn create_node(
    state: &AppState,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
    kind: FileKind,
    content: &[u8],
) -> ApiResult<DriveFile> {
    let _blob_lifecycle_lock = blob::BlobLifecycleLock::acquire_shared(&state.data_dir())?;
    let (content_hash, content_bytes) = if matches!(kind, FileKind::File) {
        (
            Some(blob::put_blob(&state.data_dir(), content)?),
            i64::try_from(content.len()).unwrap_or(i64::MAX),
        )
    } else {
        (None, 0)
    };
    let (file, _) = state.storage.create_file_with_content_bytes(
        CreateFileRequest {
            workspace_id: workspace_id.to_string(),
            parent_id: parent_id.map(str::to_string),
            name: name.to_string(),
            kind,
            content: None,
            path: None,
        },
        content_hash,
        content_bytes,
    )?;
    Ok(file)
}

fn find<'a>(files: &'a [DriveFile], file_id: &str) -> ApiResult<&'a DriveFile> {
    files
        .iter()
        .find(|file| file.id == file_id)
        .ok_or(ApiError::NotFound)
}

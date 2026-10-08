use crate::{
    auth::{Actor, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::DriveFile,
    server::AppState,
};

/// Retained files are intentionally outside live item grants. A current
/// workspace Editor or Owner may mutate retained state, while a stale
/// item-only grant cannot address a trashed file.
pub(super) fn ensure_file_state_route_write(
    state: &AppState,
    file: &DriveFile,
    actor: &Actor,
) -> ApiResult<()> {
    if file.trashed {
        match state.storage.ensure_workspace_permission(
            &file.workspace_id,
            actor,
            WorkspacePermission::Read,
        ) {
            Err(ApiError::Forbidden) => return Err(ApiError::NotFound),
            result => result?,
        }
        state.storage.ensure_workspace_permission(
            &file.workspace_id,
            actor,
            WorkspacePermission::Write,
        )
    } else {
        state
            .storage
            .ensure_item_response_permission(&file.id, actor, WorkspacePermission::Write)
            .map(|_| ())
    }
}

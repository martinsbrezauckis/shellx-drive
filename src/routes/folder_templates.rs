use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::json;

use crate::{
    auth::{require_drive_actor_with_credential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{
        ApplyFolderTemplateRequest, ApplyFolderTemplateResponse, CreateFolderTemplateRequest,
        FileKind, FolderTemplateMutationResponse,
    },
    routes::{blob_publication, metadata_response::guarded_metadata_json_with_limit_and_permit},
    server::AppState,
    storage::PreparedFolderTemplateItem,
};

// Legal workspace content can expand sixfold when JSON escapes control bytes.
// 100 templates with 256 items and 1 KiB paths need at most another 50 MiB for
// quoted paths; the remaining headroom covers bounded names, descriptions,
// identifiers, timestamps and JSON structure. Keep the 16 MiB storage budget.
const MAX_TEMPLATE_LIST_JSON_BYTES: usize = 192 * 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/workspaces/{workspace_id}/folder-templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/workspaces/{workspace_id}/folder-templates/{template_id}/apply",
            post(apply_template),
        )
        .route(
            "/workspaces/{workspace_id}/folder-templates/{template_id}",
            delete(delete_template),
        )
}

async fn list_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Read)?;
    let storage = state.storage.clone();
    let planned_workspace = workspace_id.clone();
    let (templates, planning_permit) = state
        .run_metadata_planning_retained(&actor.email, move || {
            storage.list_folder_templates_for_workspace(&planned_workspace)
        })
        .await?;
    guarded_metadata_json_with_limit_and_permit(
        &state,
        &actor.email,
        planning_permit,
        MAX_TEMPLATE_LIST_JSON_BYTES,
        || json!({ "templates": templates }),
        || {
            state.storage.ensure_workspace_publication_authorized(
                &workspace_id,
                &actor,
                &source_credential,
                WorkspacePermission::Read,
            )
        },
    )
}

async fn create_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<CreateFolderTemplateRequest>,
) -> ApiResult<(StatusCode, Json<FolderTemplateMutationResponse>)> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Write)?;
    let (template, receipt) = state.storage.create_folder_template_authorized(
        &workspace_id,
        &request.name,
        request.description,
        request.items,
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(FolderTemplateMutationResponse { template, receipt }),
    ))
}

async fn apply_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((workspace_id, template_id)): Path<(String, String)>,
    Json(request): Json<ApplyFolderTemplateRequest>,
) -> ApiResult<(StatusCode, Json<ApplyFolderTemplateResponse>)> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Write)?;
    let template = state
        .storage
        .get_folder_template(&template_id)?
        .ok_or(ApiError::NotFound)?;
    if template.workspace_id != workspace_id {
        return Err(ApiError::NotFound);
    }

    let root_name = request
        .root_name
        .as_deref()
        .unwrap_or(&template.name)
        .trim()
        .to_string();
    blob_publication::run(&state, |publications| {
        let mut prepared = Vec::with_capacity(template.items.len());
        for item in &template.items {
            if matches!(item.kind, FileKind::Folder) && item.content.is_some() {
                return Err(ApiError::Validation(
                    "folder template folders cannot contain file content".to_string(),
                ));
            }
            let content_bytes = item.content.as_ref().map_or(0, String::len) as i64;
            let content_hash = match item.content.as_deref() {
                Some(content) if matches!(item.kind, FileKind::File) => {
                    state
                        .storage
                        .ensure_workspace_server_content_allowed(&workspace_id)?;
                    Some(publications.put_bytes(content.as_bytes())?.hash)
                }
                _ => None,
            };
            prepared.push(PreparedFolderTemplateItem {
                path: item.path.clone(),
                kind: item.kind.clone(),
                content_hash,
                content_bytes,
                content_text: item.content.clone(),
            });
        }
        let (created_files, receipt) = state.storage.apply_folder_template_authorized(
            &workspace_id,
            &template_id,
            &root_name,
            prepared,
            &actor,
            &source_credential,
        )?;
        Ok((
            StatusCode::CREATED,
            Json(ApplyFolderTemplateResponse {
                template,
                created_files,
                receipt,
            }),
        ))
    })
    .await
}

async fn delete_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((workspace_id, template_id)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Write)?;
    let receipt = state.storage.delete_folder_template_authorized(
        &workspace_id,
        &template_id,
        &actor,
        &source_credential,
    )?;
    Ok(Json(json!({ "receipt": receipt })))
}

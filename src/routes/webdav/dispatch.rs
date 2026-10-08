//! DAV method dispatch and bounded request-body admission.

use axum::{
    body::{to_bytes, Body},
    extract::{Path, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    auth::{require_drive_actor, WorkspacePermission},
    error::{ApiError, ApiResult},
    server::AppState,
};

use super::{locks, operations, propfind};

const MAX_WEBDAV_LOCK_BODY_BYTES: usize = 16 * 1024;

pub(super) async fn handle_root(
    State(state): State<AppState>,
    Path(workspace_id): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    handle_dav_request(state, workspace_id, String::new(), request).await
}

pub(super) async fn handle_path(
    State(state): State<AppState>,
    Path((workspace_id, path)): Path<(String, String)>,
    request: Request,
) -> ApiResult<Response> {
    handle_dav_request(state, workspace_id, path, request).await
}

async fn handle_dav_request(
    state: AppState,
    workspace_id: String,
    path: String,
    request: Request,
) -> ApiResult<Response> {
    let method = request.method().clone();
    let headers = request.headers().clone();
    match method.as_str() {
        "PUT" => {
            // WebDAV intentionally requires a whole-workspace relationship.
            // Keep this ahead of path resolution and body consumption: item
            // grants have no root-scoped DAV protocol and therefore fail
            // closed without revealing the requested path.
            let actor = require_drive_actor(&state, &headers)?;
            state.storage.ensure_whole_workspace_permission(
                &workspace_id,
                &actor,
                WorkspacePermission::Write,
            )?;
            let ingress = state.try_authenticated_upload_ingress(&actor.email)?;
            operations::put_file(
                state,
                headers,
                workspace_id,
                path,
                request.into_body(),
                ingress,
            )
            .await
        }
        "LOCK" => {
            let actor = require_drive_actor(&state, &headers)?;
            state.storage.ensure_whole_workspace_permission(
                &workspace_id,
                &actor,
                WorkspacePermission::Write,
            )?;
            let _ingress = state.try_authenticated_upload_ingress(&actor.email)?;
            let body = to_bytes(request.into_body(), MAX_WEBDAV_LOCK_BODY_BYTES)
                .await
                .map_err(|_| {
                    ApiError::PayloadTooLarge(format!(
                        "WebDAV LOCK body exceeds {MAX_WEBDAV_LOCK_BODY_BYTES} bytes"
                    ))
                })?;
            locks::lock_path(state, headers, workspace_id, path, body).await
        }
        "OPTIONS" => options_response(),
        "PROPFIND" => propfind::propfind(state, headers, workspace_id, path).await,
        "GET" => operations::get_file(state, headers, workspace_id, path).await,
        "MKCOL" => operations::mkcol(state, headers, workspace_id, path).await,
        "DELETE" => operations::delete_path(state, headers, workspace_id, path).await,
        "MOVE" => operations::move_path(state, headers, workspace_id, path).await,
        "COPY" => operations::copy_path(state, headers, workspace_id, path).await,
        "UNLOCK" => locks::unlock_path(state, headers, workspace_id, path).await,
        _ => Ok((StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response()),
    }
}

fn options_response() -> ApiResult<Response> {
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("DAV", "1, 2")
        .header(
            header::ALLOW,
            "OPTIONS, PROPFIND, GET, PUT, MKCOL, DELETE, MOVE, COPY, LOCK, UNLOCK",
        )
        .body(Body::empty())
        .unwrap())
}

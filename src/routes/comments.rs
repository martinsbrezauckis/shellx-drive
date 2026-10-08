use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use crate::{
    auth::{require_drive_actor_with_credential, Actor, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{
        CommentMutationResponse, CommentReplyMutationResponse, CreateCommentReplyRequest,
        CreateCommentRequest, UpdateCommentRequest,
    },
    server::AppState,
};

const COMMENT_FANOUT_MUTATIONS_PER_MINUTE: i64 = 6;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/files/{file_id}/comments",
            get(list_comments).post(create_comment),
        )
        .route(
            "/comments/{comment_id}",
            axum::routing::patch(update_comment).delete(delete_comment),
        )
        .route("/comments/{comment_id}/replies", post(create_reply))
        .route(
            "/comment-replies/{reply_id}",
            axum::routing::patch(update_reply).delete(delete_reply),
        )
        .route("/comments/{comment_id}/resolve", post(resolve_comment))
}

async fn list_comments(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    let comments = state.storage.list_comments_for_file(&file_id)?;
    state.storage.ensure_item_response_publication_authorized(
        &file.id,
        &actor,
        &source_credential,
        WorkspacePermission::Read,
    )?;
    Ok(Json(json!({
        "comments": comments
    })))
}

async fn create_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Json(request): Json<CreateCommentRequest>,
) -> ApiResult<(StatusCode, Json<CommentMutationResponse>)> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    ensure_comment_fanout_budget(&state, &file.workspace_id, &actor.email)?;
    let (comment, receipt) = state.storage.create_comment_authorized(
        &file_id,
        &actor,
        &source_credential,
        &request.body,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(CommentMutationResponse { comment, receipt }),
    ))
}

async fn update_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(comment_id): Path<String>,
    Json(request): Json<UpdateCommentRequest>,
) -> ApiResult<Json<CommentMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let (comment, file) = comment_context(&state, &comment_id)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    ensure_comment_author(&actor, &comment.author_email)?;
    ensure_comment_fanout_budget(&state, &file.workspace_id, &actor.email)?;
    let (comment, receipt) = state.storage.update_comment_authorized(
        &comment_id,
        &actor,
        &source_credential,
        &request.body,
    )?;
    Ok(Json(CommentMutationResponse { comment, receipt }))
}

async fn delete_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(comment_id): Path<String>,
) -> ApiResult<Json<CommentMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let (comment, file) = comment_context(&state, &comment_id)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    ensure_comment_author(&actor, &comment.author_email)?;
    ensure_comment_fanout_budget(&state, &file.workspace_id, &actor.email)?;
    let (comment, receipt) =
        state
            .storage
            .delete_comment_authorized(&comment_id, &actor, &source_credential)?;
    Ok(Json(CommentMutationResponse { comment, receipt }))
}

async fn create_reply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(comment_id): Path<String>,
    Json(request): Json<CreateCommentReplyRequest>,
) -> ApiResult<(StatusCode, Json<CommentReplyMutationResponse>)> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let comment = state
        .storage
        .get_comment(&comment_id)?
        .ok_or(ApiError::NotFound)?;
    let file = state
        .storage
        .get_file(&comment.file_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    ensure_comment_fanout_budget(&state, &file.workspace_id, &actor.email)?;
    let (reply, receipt) = state.storage.create_comment_reply_authorized(
        &comment_id,
        &actor,
        &source_credential,
        &request.body,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(CommentReplyMutationResponse { reply, receipt }),
    ))
}

async fn update_reply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(reply_id): Path<String>,
    Json(request): Json<UpdateCommentRequest>,
) -> ApiResult<Json<CommentReplyMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let (reply, _comment, file) = reply_context(&state, &reply_id)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    ensure_comment_author(&actor, &reply.author_email)?;
    ensure_comment_fanout_budget(&state, &file.workspace_id, &actor.email)?;
    let (reply, receipt) = state.storage.update_comment_reply_authorized(
        &reply_id,
        &actor,
        &source_credential,
        &request.body,
    )?;
    Ok(Json(CommentReplyMutationResponse { reply, receipt }))
}

async fn delete_reply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(reply_id): Path<String>,
) -> ApiResult<Json<CommentReplyMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let (reply, _comment, file) = reply_context(&state, &reply_id)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    ensure_comment_author(&actor, &reply.author_email)?;
    ensure_comment_fanout_budget(&state, &file.workspace_id, &actor.email)?;
    let (reply, receipt) =
        state
            .storage
            .delete_comment_reply_authorized(&reply_id, &actor, &source_credential)?;
    Ok(Json(CommentReplyMutationResponse { reply, receipt }))
}

async fn resolve_comment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(comment_id): Path<String>,
) -> ApiResult<Json<CommentMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let comment = state
        .storage
        .get_comment(&comment_id)?
        .ok_or(ApiError::NotFound)?;
    let file = state
        .storage
        .get_file(&comment.file_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    ensure_comment_fanout_budget(&state, &file.workspace_id, &actor.email)?;
    let (comment, receipt) =
        state
            .storage
            .resolve_comment_authorized(&comment_id, &actor, &source_credential)?;
    Ok(Json(CommentMutationResponse { comment, receipt }))
}

fn ensure_comment_fanout_budget(
    state: &AppState,
    workspace_id: &str,
    actor_email: &str,
) -> ApiResult<()> {
    state.storage.consume_partitioned_fixed_window_rate_limit(
        workspace_id,
        "comment_fanout",
        actor_email,
        COMMENT_FANOUT_MUTATIONS_PER_MINUTE,
        60,
    )
}

fn comment_context(
    state: &AppState,
    comment_id: &str,
) -> ApiResult<(crate::model::CommentThread, crate::model::DriveFile)> {
    let comment = state
        .storage
        .get_comment(comment_id)?
        .ok_or(ApiError::NotFound)?;
    let file = state
        .storage
        .get_file(&comment.file_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    Ok((comment, file))
}

fn reply_context(
    state: &AppState,
    reply_id: &str,
) -> ApiResult<(
    crate::model::CommentReply,
    crate::model::CommentThread,
    crate::model::DriveFile,
)> {
    let reply = state
        .storage
        .get_comment_reply(reply_id)?
        .ok_or(ApiError::NotFound)?;
    let (comment, file) = comment_context(state, &reply.comment_id)?;
    Ok((reply, comment, file))
}

fn ensure_comment_author(actor: &Actor, author_email: &str) -> ApiResult<()> {
    if actor.is_admin || actor.email == author_email {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

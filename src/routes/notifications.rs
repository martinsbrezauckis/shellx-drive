use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::{
    auth::require_user_actor_with_credential,
    error::ApiResult,
    model::{NotificationListResponse, NotificationMutationResponse},
    server::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/notifications", get(list_notifications))
        .route("/notifications/{notification_id}/read", post(mark_read))
        .route("/notifications/read-all", post(mark_all_read))
}

#[derive(Deserialize)]
struct NotificationQuery {
    unread_only: Option<bool>,
}

async fn list_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NotificationQuery>,
) -> ApiResult<Json<NotificationListResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let visible = state
        .storage
        .list_notifications_visible_to_actor_with_credential(
            &actor,
            &source_credential,
            query.unread_only.unwrap_or(false),
        )?;
    Ok(Json(NotificationListResponse {
        unread_count: visible.unread_count,
        notifications: visible.notifications,
    }))
}

async fn mark_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(notification_id): Path<String>,
) -> ApiResult<Json<NotificationMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let (notification, receipt) =
        state
            .storage
            .mark_notification_read(&notification_id, &actor, &source_credential)?;
    Ok(Json(NotificationMutationResponse {
        notification: Some(notification),
        receipt,
    }))
}

async fn mark_all_read(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<NotificationMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let receipt = state
        .storage
        .mark_all_notifications_read(&actor, &source_credential)?;
    Ok(Json(NotificationMutationResponse {
        notification: None,
        receipt,
    }))
}

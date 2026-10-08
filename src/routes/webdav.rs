use axum::{routing::any, Router};

mod dispatch;
mod locks;
mod operations;
mod paths;
mod propfind;
mod put;
mod response;

pub(super) use crate::storage::{MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES};

use crate::server::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dav/{workspace_id}", any(dispatch::handle_root))
        .route("/dav/{workspace_id}/{*path}", any(dispatch::handle_path))
}

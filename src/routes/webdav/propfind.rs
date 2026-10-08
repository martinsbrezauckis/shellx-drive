//! PROPFIND authorization, bounded traversal, and response assembly.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use axum::{http::HeaderMap, response::Response};

use crate::{
    auth::{require_drive_actor_with_credential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
    routes::{
        blob_response::guard_bounded_bytes_response_with_total_deadline,
        content_revalidation::AuthenticatedWorkspacePublication,
    },
    server::AppState,
    storage::{MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES},
};

use super::{
    locks,
    paths::resolve_path_from_files,
    response::{append_propfind_response, file_response_xml, multistatus, root_response_xml},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DavDepth {
    Zero,
    One,
    Infinity,
}

pub(super) async fn propfind(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_whole_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Read,
    )?;
    let planning =
        state.try_metadata_planning(&format!("webdav:{}:{workspace_id}", actor.email))?;
    let stream_permit = state.try_authenticated_body_stream(&actor.email)?;
    let depth = dav_depth(&headers);
    let files = state
        .storage
        .list_active_files_for_workspace_bounded(&workspace_id, MAX_FILE_TREE_NODES)?;
    let context = locks::PropfindContext::new(&state, &workspace_id, &files, &actor)?;
    let mut responses = String::new();
    let mut published_files = Vec::new();
    let target = resolve_path_from_files(&files, &path)?;

    if let Some(target) = target {
        published_files.push(target.clone());
        append_propfind_response(
            &mut responses,
            file_response_xml(&context, &workspace_id, &target)?,
        )?;
        if matches!(target.kind, FileKind::Folder) && depth != DavDepth::Zero {
            let include_descendants = depth == DavDepth::Infinity;
            for child in children_for(&files, Some(&target.id), include_descendants)? {
                published_files.push(child.clone());
                append_propfind_response(
                    &mut responses,
                    file_response_xml(&context, &workspace_id, child)?,
                )?;
            }
        }
    } else {
        append_propfind_response(&mut responses, root_response_xml(&context, &workspace_id)?)?;
        if depth != DavDepth::Zero {
            let include_descendants = depth == DavDepth::Infinity;
            for child in children_for(&files, None, include_descendants)? {
                published_files.push(child.clone());
                append_propfind_response(
                    &mut responses,
                    file_response_xml(&context, &workspace_id, child)?,
                )?;
            }
        }
    }

    let publication = AuthenticatedWorkspacePublication::new(
        &state.storage,
        &workspace_id,
        &published_files,
        &actor,
        &source_credential,
    )?;
    publication.revalidate()?;
    let (response, encoded) = multistatus(responses)?;
    Ok(guard_bounded_bytes_response_with_total_deadline(
        response,
        encoded,
        (planning, stream_permit),
        Duration::from_secs(10 * 60),
    ))
}
fn children_for<'a>(
    files: &'a [DriveFile],
    parent_id: Option<&str>,
    include_descendants: bool,
) -> ApiResult<Vec<&'a DriveFile>> {
    let mut children_by_parent: HashMap<Option<String>, Vec<&DriveFile>> = HashMap::new();
    for file in files.iter().filter(|file| !file.trashed) {
        children_by_parent
            .entry(file.parent_id.clone())
            .or_default()
            .push(file);
    }
    for children in children_by_parent.values_mut() {
        children.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.id.cmp(&right.id))
        });
    }
    let children = children_by_parent
        .remove(&parent_id.map(str::to_string))
        .unwrap_or_default();
    ensure_unique_child_names(&children)?;
    if children.len() > MAX_FILE_TREE_NODES {
        return Err(ApiError::Validation(format!(
            "webdav file tree exceeds the {MAX_FILE_TREE_NODES}-item response limit"
        )));
    }
    if !include_descendants {
        return Ok(children);
    }

    let mut stack = children
        .into_iter()
        .rev()
        .map(|child| (child, 1_usize))
        .collect::<Vec<_>>();
    let mut all = Vec::new();
    let mut visited = HashSet::new();
    while let Some((child, depth)) = stack.pop() {
        if !visited.insert(child.id.clone()) {
            return Err(ApiError::Validation(
                "webdav file tree contains a parent cycle".to_string(),
            ));
        }
        if depth > MAX_FILE_TREE_DEPTH {
            return Err(ApiError::Validation(format!(
                "webdav file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
            )));
        }
        if all.len() >= MAX_FILE_TREE_NODES {
            return Err(ApiError::Validation(format!(
                "webdav file tree exceeds the {MAX_FILE_TREE_NODES}-item response limit"
            )));
        }
        all.push(child);
        if matches!(child.kind, FileKind::Folder) {
            let next_depth = depth.checked_add(1).ok_or_else(|| {
                ApiError::Validation("webdav file tree depth overflow".to_string())
            })?;
            if let Some(children) = children_by_parent.remove(&Some(child.id.clone())) {
                ensure_unique_child_names(&children)?;
                for nested in children.into_iter().rev() {
                    stack.push((nested, next_depth));
                }
            }
        }
    }
    Ok(all)
}

fn ensure_unique_child_names(children: &[&DriveFile]) -> ApiResult<()> {
    let mut names = HashSet::with_capacity(children.len());
    if children
        .iter()
        .any(|child| !names.insert(child.name.as_str()))
    {
        return Err(ApiError::Conflict);
    }
    Ok(())
}

fn dav_depth(headers: &HeaderMap) -> DavDepth {
    match headers
        .get("Depth")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("0") => DavDepth::Zero,
        Some("infinity") => DavDepth::Infinity,
        _ => DavDepth::One,
    }
}

#[cfg(test)]
mod tests;

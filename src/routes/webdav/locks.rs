use std::collections::{HashMap, HashSet};

use axum::{
    body::{Body, Bytes},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use super::{
    paths::{path_segments, resolve_path},
    response::{dav_href, escape_uri_segment, escape_xml, file_path},
};
use crate::{
    auth::{require_drive_actor_with_credential, Actor, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
    server::AppState,
    storage::{WebDavLock, WebDavLockDepth, WebDavMutationTarget},
};

const DEFAULT_LOCK_TIMEOUT_SECONDS: i64 = 3600;
const MAX_LOCK_BODY_BYTES: usize = 16 * 1024;
const MAX_PROPFIND_PATH_BYTES: usize = 4 * 1024 * 1024;

pub(super) struct PropfindContext {
    workspace_id: String,
    actor_email: String,
    actor_is_admin: bool,
    locks: Vec<WebDavLock>,
    lock_indices_by_resource: HashMap<Option<String>, Vec<usize>>,
    parents: HashMap<String, Option<String>>,
    paths: HashMap<String, String>,
    folders: HashSet<String>,
}

impl PropfindContext {
    pub(super) fn new(
        state: &AppState,
        workspace_id: &str,
        files: &[DriveFile],
        actor: &Actor,
    ) -> ApiResult<Self> {
        let locks = state.storage.list_active_webdav_locks(workspace_id)?;
        let mut lock_indices_by_resource: HashMap<Option<String>, Vec<usize>> = HashMap::new();
        for (index, lock) in locks.iter().enumerate() {
            lock_indices_by_resource
                .entry(lock.resource_id.clone())
                .or_default()
                .push(index);
        }
        let parents = files
            .iter()
            .map(|file| (file.id.clone(), file.parent_id.clone()))
            .collect();
        let folders = files
            .iter()
            .filter(|file| matches!(file.kind, FileKind::Folder))
            .map(|file| file.id.clone())
            .collect();
        let paths = crate::path_projection::project_file_paths(
            files,
            None,
            MAX_PROPFIND_PATH_BYTES,
            "WebDAV PROPFIND",
        )?;
        Ok(Self {
            workspace_id: workspace_id.to_string(),
            actor_email: actor.email.clone(),
            actor_is_admin: actor.is_admin,
            locks,
            lock_indices_by_resource,
            parents,
            paths,
            folders,
        })
    }

    pub(super) fn path_for(&self, resource_id: &str) -> ApiResult<&str> {
        self.paths
            .get(resource_id)
            .map(String::as_str)
            .ok_or(ApiError::NotFound)
    }

    pub(super) fn resource_properties_xml(&self, resource_id: Option<&str>) -> ApiResult<String> {
        let mut indices = self.covering_lock_indices(resource_id);
        indices.sort_unstable();
        indices.dedup();
        let discovery = indices
            .into_iter()
            .map(|index| {
                let lock = &self.locks[index];
                let root_href = self.lock_root_href(lock)?;
                Ok(active_lock_xml_with_root(
                    lock,
                    self.actor_is_admin || lock.owner_email == self.actor_email,
                    &root_href,
                ))
            })
            .collect::<ApiResult<Vec<_>>>()?
            .join("");
        Ok(format!(
            "<d:supportedlock><d:lockentry><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockentry></d:supportedlock><d:lockdiscovery>{discovery}</d:lockdiscovery>"
        ))
    }

    fn covering_lock_indices(&self, resource_id: Option<&str>) -> Vec<usize> {
        let mut result = Vec::new();
        let mut current = resource_id.map(str::to_string);
        let mut exact = true;
        loop {
            if let Some(indices) = self.lock_indices_by_resource.get(&current) {
                result.extend(indices.iter().copied().filter(|index| {
                    exact || self.locks[*index].depth == WebDavLockDepth::Infinity
                }));
            }
            let Some(resource_id) = current else {
                break;
            };
            current = self.parents.get(&resource_id).cloned().unwrap_or(None);
            exact = false;
        }
        result
    }

    fn lock_root_href(&self, lock: &WebDavLock) -> ApiResult<String> {
        let Some(resource_id) = lock.resource_id.as_deref() else {
            return Ok(format!("/dav/{}", escape_uri_segment(&self.workspace_id)));
        };
        let path = self.path_for(resource_id)?;
        Ok(dav_href(
            &self.workspace_id,
            path,
            self.folders.contains(resource_id),
        ))
    }
}

pub(super) async fn lock_path(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
    body: Bytes,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_whole_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let _webdav_operation = state.lock_webdav_operation().await;
    let resource = if path_segments(&path)?.is_empty() {
        None
    } else {
        Some(resolve_path(&state, &workspace_id, &path)?)
    };
    let resource_id = resource.as_ref().map(|file| file.id.as_str());
    let timeout_seconds = requested_timeout(&headers)?;

    if body.is_empty() {
        let tokens = submitted_tokens(&headers)?;
        if tokens.len() != 1 {
            return Err(ApiError::Validation(
                "LOCK refresh requires exactly one lock token in If".to_string(),
            ));
        }
        let token = tokens.iter().next().expect("one refresh token");
        let lock = state.storage.refresh_webdav_lock_authorized(
            &workspace_id,
            resource_id,
            token,
            timeout_seconds,
            &actor,
            &source_credential,
        )?;
        return lock_response(&state, &lock, false);
    }

    validate_lock_body(&body)?;
    let depth = requested_lock_depth(&headers)?;
    let lock = state.storage.create_webdav_lock_authorized(
        &workspace_id,
        resource_id,
        &path,
        depth,
        timeout_seconds,
        &actor,
        &source_credential,
    )?;
    lock_response(&state, &lock, true)
}

pub(super) async fn unlock_path(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_whole_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let _webdav_operation = state.lock_webdav_operation().await;
    let resource = if path_segments(&path)?.is_empty() {
        None
    } else {
        Some(resolve_path(&state, &workspace_id, &path)?)
    };
    let raw_token = headers
        .get("Lock-Token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::Validation("Lock-Token header is required".to_string()))?;
    let token = coded_url(raw_token)
        .ok_or_else(|| ApiError::Validation("Lock-Token must be a coded URL".to_string()))?;
    state.storage.unlock_webdav_lock_authorized(
        &workspace_id,
        resource.as_ref().map(|file| file.id.as_str()),
        &token,
        &actor,
        &source_credential,
    )?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(super) fn ensure_mutation_allowed(
    state: &AppState,
    headers: &HeaderMap,
    workspace_id: &str,
    targets: &[WebDavMutationTarget],
    actor_email: &str,
    actor_is_admin: bool,
) -> ApiResult<()> {
    state.storage.ensure_webdav_mutation_allowed(
        workspace_id,
        targets,
        &submitted_tokens(headers)?,
        actor_email,
        actor_is_admin,
    )
}

fn lock_response(
    state: &AppState,
    lock: &WebDavLock,
    include_token_header: bool,
) -> ApiResult<Response> {
    let body = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><d:prop xmlns:d="DAV:"><d:lockdiscovery>{}</d:lockdiscovery></d:prop>"#,
        active_lock_xml(state, lock, true)?
    );
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store");
    if include_token_header {
        builder = builder.header("Lock-Token", format!("<{}>", lock.token));
    }
    Ok(builder.body(Body::from(body)).unwrap())
}

fn active_lock_xml(state: &AppState, lock: &WebDavLock, disclose_token: bool) -> ApiResult<String> {
    let root_href = lock_root_href(state, lock)?;
    Ok(active_lock_xml_with_root(lock, disclose_token, &root_href))
}

fn active_lock_xml_with_root(lock: &WebDavLock, disclose_token: bool, root_href: &str) -> String {
    let lock_token = if disclose_token {
        format!(
            "<d:locktoken><d:href>{}</d:href></d:locktoken>",
            escape_xml(&lock.token)
        )
    } else {
        String::new()
    };
    format!(
        "<d:activelock><d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope><d:depth>{}</d:depth><d:owner><d:href>mailto:{}</d:href></d:owner><d:timeout>Second-{}</d:timeout>{}<d:lockroot><d:href>{}</d:href></d:lockroot></d:activelock>",
        lock.depth.as_str(),
        escape_xml(&lock.owner_email),
        lock.timeout_seconds,
        lock_token,
        escape_xml(root_href),
    )
}

fn lock_root_href(state: &AppState, lock: &WebDavLock) -> ApiResult<String> {
    let Some(resource_id) = &lock.resource_id else {
        return Ok(format!("/dav/{}", escape_uri_segment(&lock.workspace_id)));
    };
    let file = state
        .storage
        .get_file(resource_id)?
        .ok_or(ApiError::NotFound)?;
    let files = state
        .storage
        .list_active_files_for_workspace_bounded(&lock.workspace_id, super::MAX_FILE_TREE_NODES)?;
    let path = file_path(&files, &file)?;
    Ok(dav_href(
        &lock.workspace_id,
        &path,
        matches!(file.kind, crate::model::FileKind::Folder),
    ))
}

mod parsing;

use parsing::{
    coded_url, requested_lock_depth, requested_timeout, submitted_tokens, validate_lock_body,
};

use axum::http::HeaderMap;

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
    server::AppState,
};

#[derive(Debug)]
pub(super) struct DavDestination {
    pub parent_id: Option<String>,
    pub name: String,
}

pub(super) fn resolve_path(
    state: &AppState,
    workspace_id: &str,
    path: &str,
) -> ApiResult<DriveFile> {
    let segments = path_segments(path)?;
    if segments.is_empty() {
        return Err(ApiError::NotFound);
    }
    let mut parent_id: Option<String> = None;
    let mut current = None;
    let last_index = segments.len().saturating_sub(1);
    for (index, segment) in segments.iter().enumerate() {
        let file = active_child_by_name(state, workspace_id, parent_id.as_deref(), segment)?
            .ok_or(ApiError::NotFound)?;
        if index != last_index && !matches!(file.kind, FileKind::Folder) {
            return Err(ApiError::NotFound);
        }
        parent_id = Some(file.id.clone());
        current = Some(file);
    }
    current.ok_or(ApiError::NotFound)
}

pub(super) fn resolve_path_from_files(
    files: &[DriveFile],
    path: &str,
) -> ApiResult<Option<DriveFile>> {
    let segments = path_segments(path)?;
    if segments.is_empty() {
        return Ok(None);
    }
    let mut parent_id: Option<String> = None;
    let mut current = None;
    let last_index = segments.len().saturating_sub(1);
    for (index, segment) in segments.iter().enumerate() {
        let mut matches = files.iter().filter(|file| {
            !file.trashed
                && file.parent_id.as_deref() == parent_id.as_deref()
                && file.name == *segment
        });
        let file = matches.next().cloned().ok_or(ApiError::NotFound)?;
        if matches.next().is_some() {
            return Err(ApiError::Conflict);
        }
        if index != last_index && !matches!(file.kind, FileKind::Folder) {
            return Err(ApiError::NotFound);
        }
        parent_id = Some(file.id.clone());
        current = Some(file);
    }
    Ok(current)
}

pub(super) fn resolve_destination_path(
    state: &AppState,
    workspace_id: &str,
    path: &str,
) -> ApiResult<DavDestination> {
    let segments = path_segments(path)?;
    if segments.is_empty() {
        return Err(ApiError::Validation(
            "webdav operation requires a target name".to_string(),
        ));
    }
    let name = validate_dav_name(segments.last().unwrap())?;
    let parent_id = if segments.len() == 1 {
        None
    } else {
        let parent_path = segments[..segments.len() - 1].join("/");
        let parent = resolve_path(state, workspace_id, &parent_path)?;
        if !matches!(parent.kind, FileKind::Folder) {
            return Err(ApiError::NotFound);
        }
        Some(parent.id)
    };
    Ok(DavDestination { parent_id, name })
}

pub(super) fn ensure_destination_available(
    state: &AppState,
    workspace_id: &str,
    destination: &DavDestination,
) -> ApiResult<()> {
    if active_child_by_name(
        state,
        workspace_id,
        destination.parent_id.as_deref(),
        &destination.name,
    )?
    .is_some()
    {
        return Err(ApiError::Conflict);
    }
    Ok(())
}

pub(super) fn active_child_by_name(
    state: &AppState,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
) -> ApiResult<Option<DriveFile>> {
    state
        .storage
        .get_active_child_file_by_name(workspace_id, parent_id, name)
}

pub(super) fn path_segments(path: &str) -> ApiResult<Vec<String>> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut segments = Vec::new();
    for raw in trimmed.split('/') {
        let segment = raw.trim();
        if segment.is_empty() || segment == "." || segment == ".." || segment.contains('\\') {
            return Err(ApiError::Validation(
                "webdav path must not contain empty, dot, or backslash segments".to_string(),
            ));
        }
        segments.push(segment.to_string());
        if segments.len() > super::MAX_FILE_TREE_DEPTH + 1 {
            return Err(ApiError::Validation(format!(
                "webdav file tree exceeds the {}-level depth limit",
                super::MAX_FILE_TREE_DEPTH
            )));
        }
    }
    Ok(segments)
}

fn validate_dav_name(name: &str) -> ApiResult<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.contains('/') || trimmed == "." || trimmed == ".." {
        return Err(ApiError::Validation(
            "webdav name must be non-empty and must not contain slashes".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

pub(super) fn destination_header_path(
    headers: &HeaderMap,
    workspace_id: &str,
) -> ApiResult<String> {
    let raw = headers
        .get("Destination")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::Validation("Destination header is required".to_string()))?;
    let without_origin = if let Some(scheme_index) = raw.find("://") {
        let after_scheme = &raw[scheme_index + 3..];
        match after_scheme.find('/') {
            Some(path_index) => &after_scheme[path_index..],
            None => "/",
        }
    } else {
        raw
    };
    let without_query = without_origin
        .split(['?', '#'])
        .next()
        .unwrap_or(without_origin);
    let prefix = format!("/dav/{workspace_id}");
    let relative = if without_query == prefix {
        ""
    } else if let Some(rest) = without_query.strip_prefix(&(prefix.clone() + "/")) {
        rest
    } else {
        return Err(ApiError::Validation(
            "Destination must stay inside the same WebDAV workspace".to_string(),
        ));
    };
    percent_decode(relative)
}

fn percent_decode(value: &str) -> ApiResult<String> {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(ApiError::Validation(
                    "invalid percent encoding in WebDAV path".to_string(),
                ));
            }
            let high = hex_value(bytes[index + 1])?;
            let low = hex_value(bytes[index + 2])?;
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output)
        .map_err(|_| ApiError::Validation("WebDAV path must be valid UTF-8".to_string()))
}

fn hex_value(byte: u8) -> ApiResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ApiError::Validation(
            "invalid percent encoding in WebDAV path".to_string(),
        )),
    }
}

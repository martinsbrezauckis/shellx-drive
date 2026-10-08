//! WebDAV XML and HTTP response rendering.

use std::collections::HashSet;

use axum::{
    body::Body,
    http::{header, StatusCode},
    response::Response,
};
use chrono::{DateTime, Utc};

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
    storage::MAX_FILE_TREE_DEPTH,
};

use super::locks;

const MAX_WEBDAV_MULTISTATUS_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn multistatus(responses: String) -> ApiResult<(Response, Vec<u8>)> {
    let encoded = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">{responses}</d:multistatus>"#
    )
    .into_bytes();
    if encoded.len() > MAX_WEBDAV_MULTISTATUS_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "WebDAV PROPFIND response exceeds its {MAX_WEBDAV_MULTISTATUS_BYTES}-byte limit"
        )));
    }
    let response = Response::builder()
        .status(StatusCode::MULTI_STATUS)
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header(header::CONTENT_LENGTH, encoded.len().to_string())
        .body(Body::empty())
        .unwrap();
    Ok((response, encoded))
}

pub(super) fn append_propfind_response(responses: &mut String, response: String) -> ApiResult<()> {
    let projected = responses
        .len()
        .checked_add(response.len())
        .ok_or_else(|| ApiError::PayloadTooLarge("WebDAV response size overflow".to_string()))?;
    if projected > MAX_WEBDAV_MULTISTATUS_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "WebDAV PROPFIND response exceeds its {MAX_WEBDAV_MULTISTATUS_BYTES}-byte limit"
        )));
    }
    responses.push_str(&response);
    Ok(())
}

pub(super) fn root_response_xml(
    context: &locks::PropfindContext,
    workspace_id: &str,
) -> ApiResult<String> {
    let href = format!("/dav/{}", escape_uri_segment(workspace_id));
    Ok(resource_response_xml(
        &href,
        "ShellX Drive",
        true,
        0,
        &http_date(Utc::now()),
        &context.resource_properties_xml(None)?,
    ))
}

pub(super) fn file_response_xml(
    context: &locks::PropfindContext,
    workspace_id: &str,
    file: &DriveFile,
) -> ApiResult<String> {
    let path = context.path_for(&file.id)?;
    let is_folder = matches!(file.kind, FileKind::Folder);
    let href = dav_href(workspace_id, path, is_folder);
    let content_len = if is_folder {
        0
    } else {
        file.size_bytes.unwrap_or(0)
    };
    Ok(resource_response_xml(
        &href,
        &file.name,
        is_folder,
        content_len,
        &dav_last_modified(&file.updated_at),
        &context.resource_properties_xml(Some(&file.id))?,
    ))
}

fn resource_response_xml(
    href: &str,
    display_name: &str,
    is_folder: bool,
    content_len: i64,
    modified: &str,
    lock_properties: &str,
) -> String {
    let resource_type = if is_folder { "<d:collection/>" } else { "" };
    format!(
        "<d:response><d:href>{}</d:href><d:propstat><d:prop><d:displayname>{}</d:displayname><d:resourcetype>{}</d:resourcetype><d:getcontentlength>{}</d:getcontentlength><d:getlastmodified>{}</d:getlastmodified>{}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
        escape_xml(href),
        escape_xml(display_name),
        resource_type,
        content_len,
        escape_xml(modified),
        lock_properties,
    )
}

pub(super) fn file_path(files: &[DriveFile], file: &DriveFile) -> ApiResult<String> {
    let mut parts = vec![file.name.clone()];
    let mut parent_id = file.parent_id.clone();
    let mut visited = HashSet::from([file.id.clone()]);
    while let Some(id) = parent_id {
        if !visited.insert(id.clone()) {
            return Err(ApiError::Validation(
                "webdav parent chain contains a cycle".to_string(),
            ));
        }
        let parent = files
            .iter()
            .find(|candidate| candidate.id == id && !candidate.trashed)
            .ok_or(ApiError::NotFound)?;
        parts.push(parent.name.clone());
        parent_id = parent.parent_id.clone();
        if parts.len() > MAX_FILE_TREE_DEPTH + 1 {
            return Err(ApiError::Validation(format!(
                "webdav file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
            )));
        }
    }
    parts.reverse();
    Ok(parts.join("/"))
}

pub(super) fn dav_href(workspace_id: &str, path: &str, is_folder: bool) -> String {
    let encoded_path = path
        .split('/')
        .map(escape_uri_segment)
        .collect::<Vec<_>>()
        .join("/");
    let mut href = format!("/dav/{}/{}", escape_uri_segment(workspace_id), encoded_path);
    if is_folder && !href.ends_with('/') {
        href.push('/');
    }
    href
}

fn dav_last_modified(updated_at: &str) -> String {
    DateTime::parse_from_rfc3339(updated_at)
        .map(|value| http_date(value.with_timezone(&Utc)))
        .unwrap_or_else(|_| updated_at.to_string())
}

fn http_date(value: DateTime<Utc>) -> String {
    value.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

pub(super) fn escape_uri_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

pub(super) fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

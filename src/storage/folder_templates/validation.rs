use std::collections::HashMap;

use crate::{
    error::{ApiError, ApiResult},
    model::{CreateFolderTemplateItemRequest, FileKind},
};

use super::{
    PreparedFolderTemplateItem, MAX_FOLDER_TEMPLATE_CONTENT_BYTES,
    MAX_FOLDER_TEMPLATE_DESCRIPTION_BYTES, MAX_FOLDER_TEMPLATE_ITEMS,
    MAX_FOLDER_TEMPLATE_PATH_BYTES,
};
use crate::storage::{validate_file_name, MAX_FILE_TREE_DEPTH};

pub(super) fn normalize_description(description: Option<String>) -> ApiResult<Option<String>> {
    let description = description
        .map(|description| description.trim().to_string())
        .filter(|description| !description.is_empty());
    if description
        .as_ref()
        .is_some_and(|description| description.len() > MAX_FOLDER_TEMPLATE_DESCRIPTION_BYTES)
    {
        return Err(ApiError::PayloadTooLarge(format!(
            "folder template descriptions are limited to {MAX_FOLDER_TEMPLATE_DESCRIPTION_BYTES} bytes"
        )));
    }
    Ok(description)
}

pub(super) fn normalize_template_items(
    items: Vec<CreateFolderTemplateItemRequest>,
) -> ApiResult<Vec<CreateFolderTemplateItemRequest>> {
    if items.is_empty() || items.len() > MAX_FOLDER_TEMPLATE_ITEMS {
        return Err(ApiError::PayloadTooLarge(format!(
            "folder templates must contain 1 to {MAX_FOLDER_TEMPLATE_ITEMS} items"
        )));
    }
    let mut normalized = Vec::with_capacity(items.len());
    let mut kinds = HashMap::new();
    for item in items {
        let path = normalize_template_path(&item.path)?;
        if kinds.insert(path.clone(), item.kind.clone()).is_some() {
            return Err(ApiError::Validation(format!(
                "folder template contains duplicate path {path}"
            )));
        }
        if matches!(item.kind, FileKind::Folder) && item.content.is_some() {
            return Err(ApiError::Validation(
                "folder template folders cannot contain embedded file content".to_string(),
            ));
        }
        normalized.push(CreateFolderTemplateItemRequest {
            path,
            kind: item.kind,
            content: item.content,
        });
    }
    reject_file_ancestors(&kinds)?;
    let content_bytes = template_content_bytes(&normalized)?;
    if content_bytes > MAX_FOLDER_TEMPLATE_CONTENT_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "folder template embedded content is limited to {MAX_FOLDER_TEMPLATE_CONTENT_BYTES} bytes"
        )));
    }
    Ok(normalized)
}

pub(super) fn normalize_template_path(path: &str) -> ApiResult<String> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed.ends_with('/')
        || trimmed.len() > MAX_FOLDER_TEMPLATE_PATH_BYTES
    {
        return Err(ApiError::Validation(format!(
            "template path must be relative, non-empty, and at most {MAX_FOLDER_TEMPLATE_PATH_BYTES} bytes"
        )));
    }
    let parts = trimmed
        .split('/')
        .map(validate_file_name)
        .collect::<ApiResult<Vec<_>>>()?;
    if parts.len() + 1 > MAX_FILE_TREE_DEPTH {
        return Err(ApiError::Validation(format!(
            "template path exceeds the {MAX_FILE_TREE_DEPTH}-level tree limit"
        )));
    }
    Ok(parts.join("/"))
}

pub(super) fn template_content_bytes(
    items: &[CreateFolderTemplateItemRequest],
) -> ApiResult<usize> {
    items.iter().try_fold(0_usize, |total, item| {
        total
            .checked_add(item.content.as_ref().map_or(0, String::len))
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("folder template content size overflow".to_string())
            })
    })
}

pub(super) fn validate_prepared_template_items(
    items: &[PreparedFolderTemplateItem],
) -> ApiResult<()> {
    let mut kinds = HashMap::with_capacity(items.len());
    let mut content_bytes = 0_i64;
    for item in items {
        let path = normalize_template_path(&item.path)?;
        if kinds.insert(path.clone(), item.kind.clone()).is_some() {
            return Err(ApiError::Validation(format!(
                "folder template contains duplicate path {path}"
            )));
        }
        if item.content_bytes < 0 {
            return Err(ApiError::Validation(
                "folder template content size must not be negative".to_string(),
            ));
        }
        content_bytes = content_bytes
            .checked_add(item.content_bytes)
            .ok_or_else(|| {
                ApiError::PayloadTooLarge("folder template content size overflow".to_string())
            })?;
    }
    if content_bytes > MAX_FOLDER_TEMPLATE_CONTENT_BYTES as i64 {
        return Err(ApiError::PayloadTooLarge(format!(
            "folder template embedded content is limited to {MAX_FOLDER_TEMPLATE_CONTENT_BYTES} bytes"
        )));
    }
    reject_file_ancestors(&kinds)
}

fn reject_file_ancestors(kinds: &HashMap<String, FileKind>) -> ApiResult<()> {
    for (path, kind) in kinds {
        if !matches!(kind, FileKind::File) {
            continue;
        }
        let descendant_prefix = format!("{path}/");
        if kinds
            .keys()
            .any(|other| other.starts_with(&descendant_prefix))
        {
            return Err(ApiError::Validation(format!(
                "folder template file path {path} cannot contain descendants"
            )));
        }
    }
    Ok(())
}

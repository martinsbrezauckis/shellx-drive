use serde_json::Value;

use crate::error::{ApiError, ApiResult};

use super::{
    FileMetadataStorageProjection, JsonStorageShape, WorkspaceAuxiliaryStorageDelta,
    MAX_COMMENT_BODY_UTF8_BYTES, MAX_FILE_METADATA_JSON_ARRAYS, MAX_FILE_METADATA_JSON_DEPTH,
    MAX_FILE_METADATA_JSON_KEYS, MAX_FILE_METADATA_JSON_NODES, MAX_FILE_METADATA_JSON_SCALARS,
    MAX_FILE_METADATA_JSON_SERIALIZED_BYTES, MAX_FILE_METADATA_LABELS,
    MAX_FILE_METADATA_LABELS_SERIALIZED_BYTES, MAX_FILE_METADATA_LABEL_BYTES,
    MAX_NOTICE_SNIPPET_UTF8_BYTES,
};

/// Normalize and bound labels before serializing them into both the source
/// metadata row and the metadata portion of the FTS projection.
pub(crate) fn normalize_auxiliary_labels(labels: Vec<String>) -> ApiResult<Vec<String>> {
    let mut normalized = Vec::with_capacity(MAX_FILE_METADATA_LABELS);
    let mut too_many_labels = false;
    for label in labels {
        let label = label.trim();
        if label.is_empty() {
            continue;
        }
        let label = label.to_lowercase();
        if label.len() > MAX_FILE_METADATA_LABEL_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "metadata labels must be at most {MAX_FILE_METADATA_LABEL_BYTES} UTF-8 bytes"
            )));
        }
        if let Err(position) = normalized.binary_search(&label) {
            if normalized.len() == MAX_FILE_METADATA_LABELS {
                too_many_labels = true;
            } else {
                normalized.insert(position, label);
            }
        }
    }
    // Preserve byte-limit error precedence after checking every label.
    if too_many_labels {
        return Err(ApiError::PayloadTooLarge(format!(
            "a file supports at most {MAX_FILE_METADATA_LABELS} metadata labels"
        )));
    }
    Ok(normalized)
}

/// Serialize a metadata object after checking both its encoded size and its
/// recursively bounded shape. The caller persists the returned JSON verbatim.
pub(crate) fn validate_auxiliary_metadata_json(
    value: &Value,
) -> ApiResult<(String, JsonStorageShape)> {
    if !value.is_object() {
        return Err(ApiError::Validation(
            "custom_metadata must be a JSON object".to_string(),
        ));
    }
    let serialized = serde_json::to_string(value)
        .map_err(|error| ApiError::Validation(format!("invalid custom_metadata: {error}")))?;
    if serialized.len() > MAX_FILE_METADATA_JSON_SERIALIZED_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "custom_metadata exceeds {MAX_FILE_METADATA_JSON_SERIALIZED_BYTES} serialized UTF-8 bytes"
        )));
    }
    let mut shape = JsonStorageShape {
        serialized_bytes: serialized.len(),
        ..JsonStorageShape::default()
    };
    inspect_json_shape(value, 1, &mut shape)?;
    Ok((serialized, shape))
}

/// Produce one consistent representation for metadata admission and the two
/// storage categories it projects into.
pub(crate) fn project_file_metadata_storage(
    labels: Vec<String>,
    custom_metadata: &Value,
) -> ApiResult<FileMetadataStorageProjection> {
    let labels = normalize_auxiliary_labels(labels)?;
    let labels_json = serde_json::to_string(&labels)
        .map_err(|error| ApiError::Validation(format!("invalid labels: {error}")))?;
    if labels_json.len() > MAX_FILE_METADATA_LABELS_SERIALIZED_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "metadata labels exceed {MAX_FILE_METADATA_LABELS_SERIALIZED_BYTES} serialized UTF-8 bytes"
        )));
    }
    let (custom_json, _) = validate_auxiliary_metadata_json(custom_metadata)?;
    let metadata_bytes = checked_text_bytes(&labels_json, "metadata labels")?
        .checked_add(checked_text_bytes(&custom_json, "custom metadata")?)
        .ok_or_else(|| {
            ApiError::Validation("file metadata byte accounting overflow".to_string())
        })?;
    Ok(FileMetadataStorageProjection {
        labels,
        labels_json,
        custom_json,
        usage: WorkspaceAuxiliaryStorageDelta {
            file_metadata_bytes: metadata_bytes,
            metadata_fts_projection_bytes: metadata_bytes,
            ..WorkspaceAuxiliaryStorageDelta::default()
        },
    })
}

/// Validate a persisted metadata representation before copying or indexing it.
/// Existing legacy rows can be noncanonical; callers that replace them must
/// compute their prior accounting directly from the stored byte strings.
pub(crate) fn project_persisted_file_metadata_storage(
    labels_json: &str,
    custom_json: &str,
) -> ApiResult<FileMetadataStorageProjection> {
    let labels = serde_json::from_str::<Vec<String>>(labels_json).map_err(|error| {
        ApiError::Validation(format!("stored metadata labels are invalid: {error}"))
    })?;
    let custom_metadata = serde_json::from_str::<Value>(custom_json).map_err(|error| {
        ApiError::Validation(format!("stored custom metadata is invalid: {error}"))
    })?;
    project_file_metadata_storage(labels, &custom_metadata)
}

/// Existing source rows may predate the bounded writer. Their raw byte count
/// remains the only exact prior-side delta even when a valid replacement will
/// be canonically serialized differently.
pub(crate) fn project_raw_file_metadata_storage_usage(
    labels_json: &str,
    custom_json: &str,
) -> ApiResult<WorkspaceAuxiliaryStorageDelta> {
    let metadata_bytes = checked_text_bytes(labels_json, "stored metadata labels")?
        .checked_add(checked_text_bytes(custom_json, "stored custom metadata")?)
        .ok_or_else(|| {
            ApiError::Validation("file metadata byte accounting overflow".to_string())
        })?;
    Ok(WorkspaceAuxiliaryStorageDelta {
        file_metadata_bytes: metadata_bytes,
        metadata_fts_projection_bytes: metadata_bytes,
        ..WorkspaceAuxiliaryStorageDelta::default()
    })
}

pub(crate) fn project_comment_reply_body_storage(
    body: &str,
    kind: &str,
) -> ApiResult<WorkspaceAuxiliaryStorageDelta> {
    let body = validate_comment_body_utf8(body, kind)?;
    Ok(WorkspaceAuxiliaryStorageDelta {
        comment_reply_body_bytes: checked_text_bytes(body, "comment/reply body")?,
        ..WorkspaceAuxiliaryStorageDelta::default()
    })
}

pub(crate) fn validate_comment_body_utf8<'a>(body: &'a str, kind: &str) -> ApiResult<&'a str> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err(ApiError::Validation(format!(
            "{kind} body must not be empty"
        )));
    }
    if trimmed.len() > MAX_COMMENT_BODY_UTF8_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "{kind} body exceeds {MAX_COMMENT_BODY_UTF8_BYTES} UTF-8 bytes"
        )));
    }
    Ok(trimmed)
}

pub(crate) fn project_notification_storage(
    title: &str,
    body: &str,
) -> ApiResult<WorkspaceAuxiliaryStorageDelta> {
    let bytes = checked_text_bytes(title, "notification title")?
        .checked_add(checked_text_bytes(body, "notification body")?)
        .ok_or_else(|| ApiError::Validation("notification byte accounting overflow".to_string()))?;
    Ok(WorkspaceAuxiliaryStorageDelta {
        notification_bytes: bytes,
        ..WorkspaceAuxiliaryStorageDelta::default()
    })
}

pub(crate) fn project_workspace_email_outbox_storage(
    subject: &str,
    body_text: &str,
) -> ApiResult<WorkspaceAuxiliaryStorageDelta> {
    let bytes = checked_text_bytes(subject, "email subject")?
        .checked_add(checked_text_bytes(body_text, "email body")?)
        .ok_or_else(|| ApiError::Validation("email byte accounting overflow".to_string()))?;
    Ok(WorkspaceAuxiliaryStorageDelta {
        email_outbox_bytes: bytes,
        ..WorkspaceAuxiliaryStorageDelta::default()
    })
}

/// Produce a display-safe notice excerpt without cutting a UTF-8 sequence.
pub(crate) fn bounded_notice_snippet(value: &str) -> String {
    bounded_notice_snippet_with_limit(value, MAX_NOTICE_SNIPPET_UTF8_BYTES)
}

pub(crate) fn bounded_notice_snippet_with_limit(value: &str, maximum_bytes: usize) -> String {
    let value = value.trim();
    if value.len() <= maximum_bytes {
        return value.to_string();
    }
    let ellipsis = "…";
    if maximum_bytes < ellipsis.len() {
        return truncate_utf8(value, maximum_bytes).to_string();
    }
    let prefix = truncate_utf8(value, maximum_bytes - ellipsis.len());
    format!("{prefix}{ellipsis}")
}

fn inspect_json_shape(value: &Value, depth: usize, shape: &mut JsonStorageShape) -> ApiResult<()> {
    shape.depth = shape.depth.max(depth);
    if shape.depth > MAX_FILE_METADATA_JSON_DEPTH {
        return Err(ApiError::PayloadTooLarge(format!(
            "custom_metadata exceeds JSON depth {MAX_FILE_METADATA_JSON_DEPTH}"
        )));
    }
    increment_bounded(&mut shape.nodes, 1, MAX_FILE_METADATA_JSON_NODES, "nodes")?;
    match value {
        Value::Object(object) => {
            increment_bounded(
                &mut shape.keys,
                object.len(),
                MAX_FILE_METADATA_JSON_KEYS,
                "keys",
            )?;
            for child in object.values() {
                inspect_json_shape(child, depth + 1, shape)?;
            }
        }
        Value::Array(array) => {
            increment_bounded(
                &mut shape.arrays,
                1,
                MAX_FILE_METADATA_JSON_ARRAYS,
                "arrays",
            )?;
            for child in array {
                inspect_json_shape(child, depth + 1, shape)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            increment_bounded(
                &mut shape.scalars,
                1,
                MAX_FILE_METADATA_JSON_SCALARS,
                "scalars",
            )?;
        }
    }
    Ok(())
}

fn increment_bounded(
    current: &mut usize,
    increment: usize,
    maximum: usize,
    label: &str,
) -> ApiResult<()> {
    *current = current
        .checked_add(increment)
        .ok_or_else(|| ApiError::Validation(format!("custom_metadata {label} counter overflow")))?;
    if *current > maximum {
        return Err(ApiError::PayloadTooLarge(format!(
            "custom_metadata exceeds JSON {label} limit {maximum}"
        )));
    }
    Ok(())
}

fn checked_text_bytes(value: &str, label: &str) -> ApiResult<i64> {
    i64::try_from(value.len())
        .map_err(|_| ApiError::Validation(format!("{label} length cannot be represented")))
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> &str {
    let mut end = maximum_bytes.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::error::{ApiError, ApiResult};

use super::super::REDACTED_DATA_DIR;

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
const DEFAULT_MAX_BYTES: usize = 512 * 1024;
const MIN_MAX_BYTES: usize = 16 * 1024;
const MAX_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct ExportQuery {
    pub limit: Option<usize>,
    pub section: Option<String>,
    pub before: Option<String>,
    pub after: Option<String>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SectionStats {
    pub total_items: usize,
    pub returned_items: usize,
    pub truncated: bool,
    pub omitted_for_byte_limit: bool,
}

#[derive(Debug, Clone)]
pub(super) struct ExportLimits {
    pub limit: usize,
    pub section: Option<String>,
    pub before: Option<String>,
    pub after: Option<String>,
    pub max_bytes: usize,
}

pub(super) fn checked_limits(query: ExportQuery) -> ApiResult<ExportLimits> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    let max_bytes = query.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::Validation(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    if !(MIN_MAX_BYTES..=MAX_MAX_BYTES).contains(&max_bytes) {
        return Err(ApiError::Validation(format!(
            "max_bytes must be between {MIN_MAX_BYTES} and {MAX_MAX_BYTES}"
        )));
    }
    if query.before.as_ref().is_some_and(|value| value.len() > 64)
        || query.after.as_ref().is_some_and(|value| value.len() > 64)
    {
        return Err(ApiError::Validation(
            "time filters must be at most 64 characters".to_string(),
        ));
    }
    Ok(ExportLimits {
        limit,
        section: query.section.filter(|value| !value.trim().is_empty()),
        before: query.before.filter(|value| !value.trim().is_empty()),
        after: query.after.filter(|value| !value.trim().is_empty()),
        max_bytes,
    })
}

pub(super) fn bound_value(value: Value, limits: &ExportLimits) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .filter(|value| time_matches(value, limits))
                .take(limits.limit)
                .map(|value| bound_value(value, limits))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, bound_value(value, limits)))
                .collect(),
        ),
        scalar => scalar,
    }
}

pub(super) fn recursive_item_count(value: &Value) -> usize {
    match value {
        Value::Array(values) => values.len(),
        Value::Object(values) => values.values().map(recursive_item_count).sum(),
        _ => 0,
    }
}

pub(super) fn build_envelope(
    e2e_enabled: bool,
    limits: &ExportLimits,
    known: Vec<String>,
    catalog: Map<String, Value>,
    sections: Map<String, Value>,
) -> Value {
    let mut root = Map::from_iter([
        ("service".into(), json!("shellx-drive")),
        ("data_dir".into(), json!(REDACTED_DATA_DIR)),
        ("e2e_enabled".into(), json!(e2e_enabled)),
        ("token".into(), Value::Null),
        (
            "_export".into(),
            json!({
                "limit": limits.limit,
                "max_bytes": limits.max_bytes,
                "before": limits.before,
                "after": limits.after,
                "selected_section": limits.section,
                "available_sections": known,
                "catalog": catalog,
            }),
        ),
    ]);
    root.extend(sections);
    Value::Object(root)
}

pub(super) fn enforce_byte_limit(export: &mut Value, max_bytes: usize) {
    loop {
        let Ok(bytes) = serde_json::to_vec(export) else {
            return;
        };
        if bytes.len() <= max_bytes {
            return;
        }
        let Some(root) = export.as_object_mut() else {
            return;
        };
        let candidate = root
            .iter()
            .filter(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "service" | "data_dir" | "e2e_enabled" | "token" | "_export"
                )
            })
            .max_by_key(|(_, value)| {
                serde_json::to_vec(value)
                    .map(|bytes| bytes.len())
                    .unwrap_or(0)
            })
            .map(|(key, _)| key.clone());
        let Some(candidate) = candidate else {
            return;
        };
        root.remove(&candidate);
        if let Some(stats) = root
            .get_mut("_export")
            .and_then(|value| value.get_mut("catalog"))
            .and_then(|value| value.get_mut(&candidate))
        {
            stats["returned_items"] = json!(0);
            stats["truncated"] = json!(true);
            stats["omitted_for_byte_limit"] = json!(true);
        }
    }
}

fn time_matches(value: &Value, limits: &ExportLimits) -> bool {
    let Some(object) = value.as_object() else {
        return true;
    };
    let timestamp = [
        "created_at",
        "updated_at",
        "generated_at",
        "last_checked_at",
    ]
    .into_iter()
    .find_map(|field| object.get(field).and_then(Value::as_str));
    let Some(timestamp) = timestamp else {
        return true;
    };
    limits
        .before
        .as_deref()
        .is_none_or(|before| timestamp < before)
        && limits
            .after
            .as_deref()
            .is_none_or(|after| timestamp >= after)
}

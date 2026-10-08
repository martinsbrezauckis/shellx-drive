//! Validation for bounded actionable desktop-agent readback pages.

use serde::Deserialize;
use serde_json::Value;

use crate::error::{ApiError, ApiResult};

use super::validation::{native_review_id, MAX_NATIVE_REVIEW_ID_BYTES, MAX_OPAQUE_ID_BYTES};
use super::{
    DesktopAgentCommandPayload, DesktopAgentDesktopViewPage, DesktopAgentPairRow,
    DesktopAgentResultPayload, DesktopAgentReviewRow, DesktopAgentRootRow,
    DesktopAgentRootsDiscoveredPage, DesktopAgentViewSection,
    MAX_DESKTOP_AGENT_READBACK_LABEL_BYTES, MAX_DESKTOP_AGENT_READBACK_LIMIT,
    MAX_DESKTOP_AGENT_RESULT_BYTES,
};

const INVALID_DESKTOP_AGENT_REQUEST: &str = "invalid_desktop_agent_request";
const MAX_DESKTOP_AGENT_REVIEW_ACTIONS: usize = 8;

pub(super) fn validate_desktop_view_query(
    section: DesktopAgentViewSection,
    after: Option<&str>,
    limit: u8,
    code: &str,
) -> ApiResult<()> {
    readback_limit(limit, code)?;
    match (section, after) {
        (_, None) => Ok(()),
        (DesktopAgentViewSection::Pairs, Some(after)) => opaque_id(after, code),
        (DesktopAgentViewSection::Reviews, Some(after)) => review_cursor(after, code),
    }
}

pub(super) fn validate_roots_query(after: Option<&str>, limit: u8, code: &str) -> ApiResult<()> {
    readback_limit(limit, code)?;
    if let Some(after) = after {
        roots_cursor(after, code)?;
    }
    Ok(())
}

pub(super) fn parse_desktop_view_payload(value: Value) -> Result<DesktopAgentCommandPayload, ()> {
    let value = serde_json::from_value::<DesktopViewPayload>(value).map_err(|_| ())?;
    validate_desktop_view_query(
        value.section,
        value.after.as_deref(),
        value.limit,
        "invalid_desktop_agent_payload",
    )
    .map_err(|_| ())?;
    Ok(DesktopAgentCommandPayload::DesktopView {
        section: value.section,
        after: value.after,
        limit: value.limit,
    })
}

pub(super) fn parse_roots_payload(value: Value) -> Result<DesktopAgentCommandPayload, ()> {
    let value = serde_json::from_value::<DiscoverRootsPayload>(value).map_err(|_| ())?;
    validate_roots_query(
        value.after.as_deref(),
        value.limit,
        "invalid_desktop_agent_payload",
    )
    .map_err(|_| ())?;
    Ok(DesktopAgentCommandPayload::DiscoverRoots {
        after: value.after,
        limit: value.limit,
    })
}

pub(super) fn validate_result_bounds(
    payload: &DesktopAgentCommandPayload,
    result: &DesktopAgentResultPayload,
) -> ApiResult<()> {
    let result_bytes = serde_json::to_vec(result)
        .map_err(|_| ApiError::Validation(INVALID_DESKTOP_AGENT_REQUEST.to_string()))?;
    if result_bytes.len() > MAX_DESKTOP_AGENT_RESULT_BYTES {
        return Err(invalid());
    }

    match (payload, result) {
        (
            DesktopAgentCommandPayload::DesktopView {
                section,
                after,
                limit,
            },
            DesktopAgentResultPayload::DesktopView {
                page, next_after, ..
            },
        ) => validate_desktop_view_page(
            *section,
            after.as_deref(),
            *limit,
            page.as_ref().ok_or_else(invalid)?,
            next_after.as_deref(),
        ),
        (
            DesktopAgentCommandPayload::DiscoverRoots { after, limit },
            DesktopAgentResultPayload::RootsDiscovered {
                workspace_count,
                candidate_count,
                page,
                next_after,
                ..
            },
        ) => validate_roots_page(
            after.as_deref(),
            *limit,
            *workspace_count,
            *candidate_count,
            page.as_ref().ok_or_else(invalid)?,
            next_after.as_deref(),
        ),
        _ => Ok(()),
    }
}

fn validate_desktop_view_page(
    section: DesktopAgentViewSection,
    after: Option<&str>,
    limit: u8,
    page: &DesktopAgentDesktopViewPage,
    next_after: Option<&str>,
) -> ApiResult<()> {
    validate_desktop_view_query(section, after, limit, INVALID_DESKTOP_AGENT_REQUEST)?;
    if page.section() != section || page.after() != after || page.limit() != limit {
        return Err(invalid());
    }
    match page {
        DesktopAgentDesktopViewPage::Pairs { rows, .. } => {
            page_rows(rows.len(), limit)?;
            let mut previous = None;
            for row in rows {
                validate_pair_row(row)?;
                ordered_after(row.pair_id.as_str(), previous, after)?;
                previous = Some(row.pair_id.as_str());
            }
            next_after_pairs(rows, limit, next_after)
        }
        DesktopAgentDesktopViewPage::Reviews { rows, .. } => {
            page_rows(rows.len(), limit)?;
            let mut previous = None;
            for row in rows {
                validate_review_row(row)?;
                let cursor = review_row_cursor(row);
                ordered_after(&cursor, previous.as_deref(), after)?;
                previous = Some(cursor);
            }
            next_after_reviews(rows, limit, next_after)
        }
    }
}

fn validate_roots_page(
    after: Option<&str>,
    limit: u8,
    workspace_count: u16,
    candidate_count: u16,
    page: &DesktopAgentRootsDiscoveredPage,
    next_after: Option<&str>,
) -> ApiResult<()> {
    validate_roots_query(after, limit, INVALID_DESKTOP_AGENT_REQUEST)?;
    if page.after.as_deref() != after || page.limit != limit {
        return Err(invalid());
    }
    page_rows(page.rows.len(), limit)?;
    let mut root_ids = std::collections::BTreeSet::new();
    let mut workspace_ids = std::collections::BTreeSet::new();
    for row in &page.rows {
        validate_root_row(row)?;
        if !root_ids.insert(row.sync_root_id.as_str()) {
            return Err(invalid());
        }
        workspace_ids.insert(row.workspace_id.as_str());
    }
    if usize::from(candidate_count) < page.rows.len()
        || usize::from(workspace_count) < workspace_ids.len()
    {
        return Err(invalid());
    }
    next_after_roots(after, next_after)
}

fn validate_pair_row(row: &DesktopAgentPairRow) -> ApiResult<()> {
    opaque_id(&row.pair_id, INVALID_DESKTOP_AGENT_REQUEST)?;
    opaque_id(&row.workspace_id, INVALID_DESKTOP_AGENT_REQUEST)?;
    label(&row.workspace_name)?;
    optional_opaque_id(row.remote_root_id.as_deref())?;
    optional_label(row.remote_root_name.as_deref())
}

fn validate_review_row(row: &DesktopAgentReviewRow) -> ApiResult<()> {
    native_review_id(&row.review_id, INVALID_DESKTOP_AGENT_REQUEST)?;
    opaque_id(&row.pair_id, INVALID_DESKTOP_AGENT_REQUEST)?;
    label(&row.item_label)?;
    if row.actions.len() > MAX_DESKTOP_AGENT_REVIEW_ACTIONS
        || row
            .actions
            .iter()
            .enumerate()
            .any(|(index, action)| row.actions[..index].contains(action))
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_root_row(row: &DesktopAgentRootRow) -> ApiResult<()> {
    opaque_id(&row.workspace_id, INVALID_DESKTOP_AGENT_REQUEST)?;
    opaque_id(&row.sync_root_id, INVALID_DESKTOP_AGENT_REQUEST)?;
    optional_opaque_id(row.remote_root_id.as_deref())?;
    label(&row.workspace_name)?;
    label(&row.root_name)?;
    label(&row.owner_label)
}

fn next_after_pairs(
    rows: &[DesktopAgentPairRow],
    limit: u8,
    next_after: Option<&str>,
) -> ApiResult<()> {
    next_after_for_last(
        rows.len(),
        limit,
        rows.last().map(|row| row.pair_id.as_str()),
        next_after,
        |cursor| opaque_id(cursor, INVALID_DESKTOP_AGENT_REQUEST),
    )
}

fn next_after_reviews(
    rows: &[DesktopAgentReviewRow],
    limit: u8,
    next_after: Option<&str>,
) -> ApiResult<()> {
    let last = rows.last().map(review_row_cursor);
    match next_after {
        None => Ok(()),
        Some(cursor)
            if !rows.is_empty()
                && rows.len() <= usize::from(limit)
                && last.as_deref() == Some(cursor) =>
        {
            review_cursor(cursor, INVALID_DESKTOP_AGENT_REQUEST)
        }
        Some(_) => Err(invalid()),
    }
}

fn next_after_roots(after: Option<&str>, next_after: Option<&str>) -> ApiResult<()> {
    match next_after {
        None => Ok(()),
        Some(cursor) if Some(cursor) != after => {
            roots_cursor(cursor, INVALID_DESKTOP_AGENT_REQUEST)
        }
        Some(_) => Err(invalid()),
    }
}

fn roots_cursor(value: &str, code: &str) -> ApiResult<()> {
    if value.is_empty()
        || value.len() > 2048
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ApiError::Validation(code.to_string()));
    }
    Ok(())
}

fn next_after_for_last(
    row_count: usize,
    limit: u8,
    last: Option<&str>,
    next_after: Option<&str>,
    validate_cursor: impl FnOnce(&str) -> ApiResult<()>,
) -> ApiResult<()> {
    match next_after {
        None => Ok(()),
        Some(next_after) if row_count == usize::from(limit) && last == Some(next_after) => {
            validate_cursor(next_after)
        }
        Some(_) => Err(invalid()),
    }
}

fn ordered_after(current: &str, previous: Option<&str>, after: Option<&str>) -> ApiResult<()> {
    if previous.is_some_and(|previous| previous >= current)
        || after.is_some_and(|after| current <= after)
    {
        return Err(invalid());
    }
    Ok(())
}

fn review_row_cursor(row: &DesktopAgentReviewRow) -> String {
    format!("{}/{}", row.pair_id, row.review_id)
}

fn readback_limit(limit: u8, code: &str) -> ApiResult<()> {
    if !(1..=MAX_DESKTOP_AGENT_READBACK_LIMIT).contains(&limit) {
        return Err(ApiError::Validation(code.to_string()));
    }
    Ok(())
}

fn page_rows(rows: usize, limit: u8) -> ApiResult<()> {
    if rows > usize::from(limit) || rows > usize::from(MAX_DESKTOP_AGENT_READBACK_LIMIT) {
        return Err(invalid());
    }
    Ok(())
}

fn optional_opaque_id(value: Option<&str>) -> ApiResult<()> {
    if let Some(value) = value {
        opaque_id(value, INVALID_DESKTOP_AGENT_REQUEST)?;
    }
    Ok(())
}

fn optional_label(value: Option<&str>) -> ApiResult<()> {
    if let Some(value) = value {
        label(value)?;
    }
    Ok(())
}

fn review_cursor(value: &str, code: &str) -> ApiResult<()> {
    if value.len() > MAX_OPAQUE_ID_BYTES + 1 + MAX_NATIVE_REVIEW_ID_BYTES {
        return Err(ApiError::Validation(code.to_string()));
    }
    let (pair_id, review_id) = value
        .split_once('/')
        .ok_or_else(|| ApiError::Validation(code.to_string()))?;
    opaque_id(pair_id, code)?;
    native_review_id(review_id, code)
}

fn opaque_id(value: &str, code: &str) -> ApiResult<()> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(ApiError::Validation(code.to_string()));
    }
    Ok(())
}

fn label(value: &str) -> ApiResult<()> {
    let is_windows_absolute = value.len() >= 3
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.as_bytes()[1] == b':'
        && matches!(value.as_bytes()[2], b'/' | b'\\');
    if value.is_empty()
        || value.len() > MAX_DESKTOP_AGENT_READBACK_LABEL_BYTES
        || value.starts_with('/')
        || value.starts_with('\\')
        || is_windows_absolute
        || value.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> ApiError {
    ApiError::Validation(INVALID_DESKTOP_AGENT_REQUEST.to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopViewPayload {
    #[serde(default)]
    section: DesktopAgentViewSection,
    #[serde(default)]
    after: Option<String>,
    #[serde(default = "default_readback_limit")]
    limit: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoverRootsPayload {
    #[serde(default)]
    after: Option<String>,
    #[serde(default = "default_readback_limit")]
    limit: u8,
}

const fn default_readback_limit() -> u8 {
    super::DEFAULT_DESKTOP_AGENT_READBACK_LIMIT
}

#[cfg(test)]
#[path = "readback_validation/tests.rs"]
mod tests;

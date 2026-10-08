//! Bounded product-data pages for desktop-agent readback.

use serde::{Deserialize, Serialize};

use crate::{DesktopError, Result, ReviewAction, ReviewKind, SyncRootRole};

use super::fingerprint::{ensure_native_review_id, MAX_NATIVE_REVIEW_ID_BYTES};

const DEFAULT_PAGE_LIMIT: u8 = 25;
pub const MAX_DESKTOP_AGENT_PAGE_ROWS: u8 = 50;
pub const MAX_DESKTOP_AGENT_PAGE_BYTES: usize = 64 * 1024;
const MAX_CURSOR_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentDesktopViewSection {
    Pairs,
    Reviews,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DesktopAgentDesktopViewPageRequest {
    pub section: DesktopAgentDesktopViewSection,
    pub after: Option<String>,
    pub limit: u8,
}

impl Default for DesktopAgentDesktopViewPageRequest {
    fn default() -> Self {
        Self {
            section: DesktopAgentDesktopViewSection::Pairs,
            after: None,
            limit: DEFAULT_PAGE_LIMIT,
        }
    }
}

impl DesktopAgentDesktopViewPageRequest {
    pub fn new(
        section: Option<DesktopAgentDesktopViewSection>,
        after: Option<String>,
        limit: Option<u8>,
    ) -> Result<Self> {
        let page = Self {
            section: section.unwrap_or(DesktopAgentDesktopViewSection::Pairs),
            after,
            limit: limit.unwrap_or(DEFAULT_PAGE_LIMIT),
        };
        page.validate()?;
        Ok(page)
    }

    pub fn validate(&self) -> Result<()> {
        validate_limit(self.limit)?;
        match (self.section, self.after.as_deref()) {
            (_, None) => Ok(()),
            (DesktopAgentDesktopViewSection::Pairs, Some(after)) => {
                validate_id("pair cursor", after)
            }
            (DesktopAgentDesktopViewSection::Reviews, Some(after)) => validate_review_cursor(after),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DesktopAgentRootsPageRequest {
    pub after: Option<String>,
    pub limit: u8,
}

impl Default for DesktopAgentRootsPageRequest {
    fn default() -> Self {
        Self {
            after: None,
            limit: DEFAULT_PAGE_LIMIT,
        }
    }
}

impl DesktopAgentRootsPageRequest {
    pub fn new(after: Option<String>, limit: Option<u8>) -> Result<Self> {
        let page = Self {
            after,
            limit: limit.unwrap_or(DEFAULT_PAGE_LIMIT),
        };
        page.validate()?;
        Ok(page)
    }

    pub fn validate(&self) -> Result<()> {
        validate_limit(self.limit)?;
        self.after
            .as_deref()
            .map(validate_root_cursor)
            .transpose()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentPairStatus {
    Ready,
    Paused,
    NeedsReview,
    Error,
    Managed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAgentRootSelectionStatus {
    Available,
    Configured,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentPairRow {
    pub pair_id: String,
    pub workspace_id: String,
    pub workspace_name: String,
    pub remote_root_id: Option<String>,
    pub remote_root_name: Option<String>,
    pub selected: bool,
    pub status: DesktopAgentPairStatus,
    pub pending_review_count: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentReviewRow {
    pub review_id: String,
    pub pair_id: String,
    pub item_label: String,
    pub reason: ReviewKind,
    pub actions: Vec<ReviewAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentRootRow {
    pub workspace_id: String,
    pub workspace_name: String,
    pub sync_root_id: String,
    pub remote_root_id: Option<String>,
    pub root_name: String,
    pub owner_label: String,
    pub role: SyncRootRole,
    pub selection_status: DesktopAgentRootSelectionStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "section", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopAgentDesktopViewPage {
    Pairs {
        after: Option<String>,
        limit: u8,
        rows: Vec<DesktopAgentPairRow>,
    },
    Reviews {
        after: Option<String>,
        limit: u8,
        rows: Vec<DesktopAgentReviewRow>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAgentRootsPage {
    pub after: Option<String>,
    pub limit: u8,
    pub rows: Vec<DesktopAgentRootRow>,
}

impl DesktopAgentDesktopViewPage {
    pub fn validate(&self, next_after: Option<&str>) -> Result<()> {
        match self {
            Self::Pairs { after, limit, rows } => {
                DesktopAgentDesktopViewPageRequest::new(None, after.clone(), Some(*limit))?;
                validate_pairs(rows, after.as_deref())?;
                if next_after.is_some() && rows.len() != usize::from(*limit) {
                    return Err(DesktopError::InvalidState(
                        "desktop-agent next pair page requires a full page".to_string(),
                    ));
                }
                validate_next(
                    next_after,
                    *limit,
                    rows.len(),
                    rows.last().map(|row| row.pair_id.clone()),
                )
            }
            Self::Reviews { after, limit, rows } => {
                DesktopAgentDesktopViewPageRequest::new(
                    Some(DesktopAgentDesktopViewSection::Reviews),
                    after.clone(),
                    Some(*limit),
                )?;
                validate_reviews(rows, after.as_deref())?;
                validate_next(
                    next_after,
                    *limit,
                    rows.len(),
                    rows.last().map(review_cursor),
                )
            }
        }
    }
}

impl DesktopAgentRootsPage {
    pub fn validate(&self, next_after: Option<&str>) -> Result<()> {
        DesktopAgentRootsPageRequest::new(self.after.clone(), Some(self.limit))?;
        validate_roots(&self.rows)?;
        if self.rows.len() > usize::from(self.limit) {
            return Err(DesktopError::InvalidState(
                "desktop-agent root page exceeds its requested limit".to_string(),
            ));
        }
        if let Some(next) = next_after {
            validate_root_cursor(next)?;
            if self.after.as_deref() == Some(next) {
                return Err(DesktopError::InvalidState(
                    "desktop-agent root cursor did not advance".to_string(),
                ));
            }
        }
        Ok(())
    }
}

pub fn review_cursor(row: &DesktopAgentReviewRow) -> String {
    format!("{}/{}", row.pair_id, row.review_id)
}

pub fn validate_page_result<T: Serialize>(value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        DesktopError::InvalidState("desktop-agent page is not serializable".to_string())
    })?;
    if bytes.len() > MAX_DESKTOP_AGENT_PAGE_BYTES {
        return Err(DesktopError::InvalidState(
            "desktop-agent page exceeds its result limit".to_string(),
        ));
    }
    Ok(())
}

pub fn product_label(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if character.is_control() || character == '\\' {
            continue;
        }
        if output.len() + character.len_utf8() > MAX_LABEL_BYTES {
            break;
        }
        output.push(character);
    }
    let output = output.trim_start_matches('/').trim().to_string();
    if output.is_empty()
        || (output.as_bytes().get(1) == Some(&b':')
            && output
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic))
    {
        "item".to_string()
    } else {
        output
    }
}

fn validate_pairs(rows: &[DesktopAgentPairRow], after: Option<&str>) -> Result<()> {
    validate_rows(rows.len())?;
    let mut previous = after;
    for row in rows {
        validate_id("pair ID", &row.pair_id)?;
        validate_id("workspace ID", &row.workspace_id)?;
        validate_label("workspace name", &row.workspace_name)?;
        validate_optional_id("remote root ID", row.remote_root_id.as_deref())?;
        validate_optional_label("remote root name", row.remote_root_name.as_deref())?;
        validate_order(previous, &row.pair_id)?;
        previous = Some(&row.pair_id);
    }
    Ok(())
}

fn validate_reviews(rows: &[DesktopAgentReviewRow], after: Option<&str>) -> Result<()> {
    validate_rows(rows.len())?;
    let mut previous = after.map(str::to_owned);
    for row in rows {
        ensure_native_review_id(&row.review_id)?;
        validate_id("review pair ID", &row.pair_id)?;
        validate_label("review item label", &row.item_label)?;
        if row.actions.len() > 8
            || row
                .actions
                .iter()
                .enumerate()
                .any(|(index, action)| row.actions[..index].contains(action))
        {
            return Err(DesktopError::InvalidState(
                "desktop-agent review actions must be unique and bounded".to_string(),
            ));
        }
        let cursor = review_cursor(row);
        validate_review_cursor(&cursor)?;
        validate_order(previous.as_deref(), &cursor)?;
        previous = Some(cursor);
    }
    Ok(())
}

fn validate_roots(rows: &[DesktopAgentRootRow]) -> Result<()> {
    validate_rows(rows.len())?;
    let mut observed = std::collections::BTreeSet::new();
    for row in rows {
        validate_id("root workspace ID", &row.workspace_id)?;
        validate_label("root workspace name", &row.workspace_name)?;
        validate_id("sync root ID", &row.sync_root_id)?;
        validate_optional_id("root remote ID", row.remote_root_id.as_deref())?;
        validate_label("root name", &row.root_name)?;
        validate_label("root owner label", &row.owner_label)?;
        if !observed.insert(row.sync_root_id.as_str()) {
            return Err(DesktopError::InvalidState(
                "desktop-agent root page repeats a root".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_next(
    next: Option<&str>,
    limit: u8,
    row_count: usize,
    last: Option<String>,
) -> Result<()> {
    if row_count > usize::from(limit) {
        return Err(DesktopError::InvalidState(
            "desktop-agent page exceeds its requested limit".to_string(),
        ));
    }
    let Some(next) = next else {
        return Ok(());
    };
    if row_count == 0 || last.as_deref() != Some(next) {
        return Err(DesktopError::InvalidState(
            "desktop-agent next page requires a nonempty page and its final cursor".to_string(),
        ));
    }
    validate_limit(limit)
}

fn validate_rows(rows: usize) -> Result<()> {
    if rows > usize::from(MAX_DESKTOP_AGENT_PAGE_ROWS) {
        return Err(DesktopError::InvalidState(
            "desktop-agent page has too many rows".to_string(),
        ));
    }
    Ok(())
}

fn validate_limit(limit: u8) -> Result<()> {
    if !(1..=MAX_DESKTOP_AGENT_PAGE_ROWS).contains(&limit) {
        return Err(DesktopError::InvalidState(
            "desktop-agent page limit must be between 1 and 50".to_string(),
        ));
    }
    Ok(())
}

fn validate_order(previous: Option<&str>, current: &str) -> Result<()> {
    if previous.is_some_and(|previous| previous >= current) {
        return Err(DesktopError::InvalidState(
            "desktop-agent page rows are not in stable cursor order".to_string(),
        ));
    }
    Ok(())
}

fn validate_review_cursor(cursor: &str) -> Result<()> {
    if cursor.len() > MAX_CURSOR_BYTES + 1 + MAX_NATIVE_REVIEW_ID_BYTES {
        return Err(DesktopError::InvalidState(
            "desktop-agent review cursor exceeds its limit".to_string(),
        ));
    }
    let Some((pair_id, review_id)) = cursor.split_once('/') else {
        return Err(DesktopError::InvalidState(
            "desktop-agent review cursor must contain pair and review IDs".to_string(),
        ));
    };
    validate_id("review pair cursor", pair_id)?;
    ensure_native_review_id(review_id)
}

fn validate_optional_id(label: &str, value: Option<&str>) -> Result<()> {
    value.map(|value| validate_id(label, value)).transpose()?;
    Ok(())
}

fn validate_optional_label(label: &str, value: Option<&str>) -> Result<()> {
    value
        .map(|value| validate_label(label, value))
        .transpose()?;
    Ok(())
}

fn validate_id(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_CURSOR_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(DesktopError::InvalidState(format!(
            "desktop-agent {label} must be a bounded stable ID"
        )));
    }
    Ok(())
}

fn validate_root_cursor(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 2_048
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(DesktopError::InvalidState(
            "desktop-agent root cursor is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_label(label: &str, value: &str) -> Result<()> {
    let drive_prefix = value.as_bytes().get(1) == Some(&b':')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic);
    if value.is_empty()
        || value.len() > MAX_LABEL_BYTES
        || value.starts_with('/')
        || value.starts_with('\\')
        || drive_prefix
        || value
            .chars()
            .any(|character| character.is_control() || character == '\\')
    {
        return Err(DesktopError::InvalidState(format!(
            "desktop-agent {label} is not a bounded product label"
        )));
    }
    Ok(())
}

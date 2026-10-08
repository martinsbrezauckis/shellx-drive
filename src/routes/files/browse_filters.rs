use chrono::DateTime;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    storage::FileBrowseFilters,
};

#[derive(Deserialize)]
pub(super) struct BrowseQuery {
    pub(super) scope: Option<String>,
    pub(super) limit: Option<usize>,
    pub(super) cursor: Option<String>,
    pub(super) type_filter: Option<String>,
    pub(super) owner_scope: Option<String>,
    pub(super) modified_since: Option<String>,
    pub(super) workspace_id: Option<String>,
    pub(super) folder_id: Option<String>,
    pub(super) state_filter: Option<String>,
}

pub(super) fn validate_browse_filters(query: &BrowseQuery) -> ApiResult<FileBrowseFilters> {
    fn selected(value: &Option<String>, allowed: &[&str], name: &str) -> ApiResult<Option<String>> {
        match value.as_deref() {
            None | Some("any") | Some("all") => Ok(None),
            Some(value) if allowed.contains(&value) => Ok(Some(value.to_string())),
            _ => Err(ApiError::Validation(format!("invalid {name} filter"))),
        }
    }
    let workspace_id = query
        .workspace_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| ApiError::Validation("invalid workspace filter".to_string()))?
        .map(|value| value.hyphenated().to_string());
    let folder_id = query
        .folder_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| ApiError::Validation("invalid folder filter".to_string()))?
        .map(|value| value.hyphenated().to_string());
    if folder_id.is_some() && workspace_id.is_none() {
        return Err(ApiError::Validation(
            "folder filter requires a workspace".to_string(),
        ));
    }
    let modified_since = match query.modified_since.as_deref() {
        None => None,
        Some(value) if value.len() <= 40 && DateTime::parse_from_rfc3339(value).is_ok() => {
            Some(value.to_string())
        }
        _ => return Err(ApiError::Validation("invalid modified filter".to_string())),
    };
    Ok(FileBrowseFilters {
        type_filter: selected(
            &query.type_filter,
            &[
                "folders", "docs", "sheets", "pdfs", "images", "videos", "audio", "archives",
            ],
            "type",
        )?,
        owner_scope: selected(&query.owner_scope, &["owned", "shared"], "owner")?,
        modified_since,
        workspace_id,
        folder_id,
        state_filter: selected(
            &query.state_filter,
            &["shared", "starred", "offline"],
            "state",
        )?,
    })
}

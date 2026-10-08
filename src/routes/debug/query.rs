use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};

pub(super) const DEFAULT_LIMIT: usize = 50;
pub(super) const MAX_LIMIT: usize = 200;

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct BoundedListQuery {
    pub limit: Option<usize>,
    pub before: Option<String>,
    pub kind: Option<String>,
}

impl BoundedListQuery {
    pub(super) fn checked_limit(&self) -> ApiResult<usize> {
        let limit = self.limit.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(ApiError::Validation(format!(
                "limit must be between 1 and {MAX_LIMIT}"
            )));
        }
        Ok(limit)
    }

    pub(super) fn normalized_before(&self) -> Option<&str> {
        self.before
            .as_deref()
            .filter(|value| !value.trim().is_empty())
    }

    pub(super) fn normalized_kind(&self) -> Option<&str> {
        self.kind
            .as_deref()
            .filter(|value| !value.trim().is_empty())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BoundedSnapshotQuery {
    pub limit: Option<usize>,
}

impl BoundedSnapshotQuery {
    pub(super) fn checked_limit(&self) -> ApiResult<usize> {
        let limit = self.limit.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(ApiError::Validation(format!(
                "limit must be between 1 and {MAX_LIMIT}"
            )));
        }
        Ok(limit)
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct PageMeta {
    pub total: i64,
    pub returned: usize,
    pub limit: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before: Option<String>,
}

impl PageMeta {
    pub(super) fn new(
        total: i64,
        returned: usize,
        limit: usize,
        next_before: Option<String>,
    ) -> Self {
        Self {
            total,
            returned,
            limit,
            truncated: total > returned as i64,
            next_before,
        }
    }
}

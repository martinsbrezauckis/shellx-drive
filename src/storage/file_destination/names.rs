use rusqlite::Transaction;

use crate::error::{ApiError, ApiResult};

use super::{super::derived_names::derive_copy_file_name, active::live_sibling_exists_in_tx};

/// Return an available keep-both name while the caller holds the immediate
/// write transaction. Existing legacy duplicate rows are left untouched, but
/// new rows never add another ambiguous active sibling.
pub(in crate::storage) fn available_copy_name_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
    parent_id: Option<&str>,
    requested_name: &str,
) -> ApiResult<String> {
    available_copy_name_excluding_in_tx(tx, workspace_id, parent_id, requested_name, None)
}

pub(super) fn available_copy_name_excluding_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
    parent_id: Option<&str>,
    requested_name: &str,
    excluded_file_id: Option<&str>,
) -> ApiResult<String> {
    if !live_sibling_exists_in_tx(
        tx,
        workspace_id,
        parent_id,
        requested_name,
        excluded_file_id,
    )? {
        return Ok(requested_name.to_string());
    }
    for sequence in 1..=10_001 {
        let candidate = derive_copy_file_name(requested_name, sequence)?;
        if !live_sibling_exists_in_tx(tx, workspace_id, parent_id, &candidate, excluded_file_id)? {
            return Ok(candidate);
        }
    }
    Err(ApiError::PayloadTooLarge(
        "destination has too many similarly named active files".to_string(),
    ))
}

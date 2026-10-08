use std::collections::HashSet;

use rusqlite::Transaction;

use crate::{
    error::{ApiError, ApiResult},
    model::DriveFile,
};

use super::active::live_sibling_exists_in_tx;

/// Restoring a retained root makes its old destination active again. Reject a
/// restore that would recreate an ambiguous active path; retained records stay
/// untouched so the caller can rename or otherwise resolve the collision.
pub(in crate::storage) fn ensure_restore_destinations_available_in_tx(
    tx: &Transaction<'_>,
    roots: &[DriveFile],
) -> ApiResult<()> {
    let mut restored_destinations = HashSet::with_capacity(roots.len());
    for root in roots {
        let destination = (
            root.workspace_id.clone(),
            root.parent_id.clone(),
            root.name.clone(),
        );
        if !restored_destinations.insert(destination)
            || live_sibling_exists_in_tx(
                tx,
                &root.workspace_id,
                root.parent_id.as_deref(),
                &root.name,
                None,
            )?
        {
            return Err(ApiError::Conflict);
        }
    }
    Ok(())
}

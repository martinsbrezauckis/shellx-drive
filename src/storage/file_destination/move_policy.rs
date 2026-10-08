use rusqlite::Transaction;

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
};

use super::{lookup::active_sibling_in_tx, names::available_copy_name_excluding_in_tx};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::storage) enum DestinationCollisionPolicy {
    KeepBoth,
    Replace,
    Cancel,
}

pub(in crate::storage) enum ResolvedMoveDestination {
    Move(String),
    Replace(DriveFile),
}

/// Parse the user-selected collision policy. `skip` remains a compatibility
/// spelling for Cancel from the earlier resumable-upload contract.
pub(in crate::storage) fn parse_destination_collision_policy(
    policy: Option<&str>,
) -> ApiResult<DestinationCollisionPolicy> {
    match policy.unwrap_or("keep_both") {
        "keep_both" => Ok(DestinationCollisionPolicy::KeepBoth),
        "replace" => Ok(DestinationCollisionPolicy::Replace),
        "cancel" | "skip" => Ok(DestinationCollisionPolicy::Cancel),
        _ => Err(ApiError::Validation(
            "collision_policy must be keep_both, replace, or cancel".to_string(),
        )),
    }
}

/// Resolve an explicit move/rename collision while the immediate transaction
/// is held. Keep-both derives a free name atomically. Replace is restricted to
/// regular files and returns the occupied canonical destination for the caller
/// to replace after it has rechecked authority and both revisions.
pub(in crate::storage) fn resolve_move_destination_in_tx(
    tx: &Transaction<'_>,
    source: &DriveFile,
    parent_id: Option<&str>,
    requested_name: &str,
    policy: DestinationCollisionPolicy,
    _updated_at: &str,
) -> ApiResult<ResolvedMoveDestination> {
    if parent_id != source.parent_id.as_deref() {
        super::move_depth::validate_move_depth_in_tx(tx, source, parent_id)?;
    }
    let Some(occupied) = active_sibling_in_tx(
        tx,
        &source.workspace_id,
        parent_id,
        requested_name,
        Some(&source.id),
    )?
    else {
        return Ok(ResolvedMoveDestination::Move(requested_name.to_string()));
    };
    match policy {
        DestinationCollisionPolicy::KeepBoth => available_copy_name_excluding_in_tx(
            tx,
            &source.workspace_id,
            parent_id,
            requested_name,
            Some(&source.id),
        )
        .map(ResolvedMoveDestination::Move),
        DestinationCollisionPolicy::Cancel => Err(ApiError::Conflict),
        DestinationCollisionPolicy::Replace => {
            if !matches!(source.kind, FileKind::File) || !matches!(occupied.kind, FileKind::File) {
                return Err(ApiError::Validation(
                    "replace is available only when both collision items are files".to_string(),
                ));
            }
            Ok(ResolvedMoveDestination::Replace(occupied))
        }
    }
}

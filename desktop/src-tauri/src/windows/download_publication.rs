//! Final race checks and native publication for verified inbound bodies.

use std::path::Path;

#[cfg(test)]
use std::{fs, os::windows::fs::OpenOptionsExt};

use super::*;
use super::{
    replacement_guard::{publish_replacing_staged_file, FrozenDestination, ReplacementOutcome},
    verified_staging::{move_verified_staged_file, VerifiedStagedFile},
};

pub(super) fn download_race_review(path: &Path) -> ReviewItem {
    ReviewItem {
        id: format!("download-race:{}", path.display()),
        kind: ReviewKind::ContentConflict,
        relative_path: path.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary: "Local state changed while the Drive body was downloading. Local bytes and the remote Drive body were preserved; no overwrite was attempted.".to_string(),
        actions: vec![ReviewAction::OpenConflictCopies],
    }
}

fn planned_conflict_copy_review_index(
    reviews: &[ReviewItem],
    conflict_path: &Path,
) -> CoreResult<usize> {
    reviews
        .iter()
        .position(|review| {
            review.kind == ReviewKind::ContentConflict
                && review.relative_path == conflict_path
                && review.actions == [ReviewAction::OpenConflictCopies]
        })
        .ok_or_else(|| {
            DesktopError::InvalidState(format!(
                "conflict-copy action has no matching visible content-conflict review: {}",
                conflict_path.display()
            ))
        })
}

/// Do this before transferring a conflict copy so an unbound future planner
/// action cannot publish bytes without the review that explains the copy.
pub(super) fn validate_planned_conflict_copy_review(
    reviews: &[ReviewItem],
    conflict_path: &Path,
) -> CoreResult<()> {
    planned_conflict_copy_review_index(reviews, conflict_path).map(|_| ())
}

/// Keep the planner's stable content-conflict identity, but replace its
/// optimistic keep-both text with the outcome observed at publication time.
/// A race cannot leave a review claiming the conflict copy was written.
pub(super) fn merge_conflict_copy_publication_review(
    reviews: &mut [ReviewItem],
    conflict_path: &Path,
    publication: DownloadPublication,
) -> CoreResult<()> {
    let index = planned_conflict_copy_review_index(reviews, conflict_path)?;
    let DownloadPublication::NeedsReview { mut review } = publication else {
        return Ok(());
    };
    review.id = reviews[index].id.clone();
    reviews[index] = review;
    Ok(())
}

fn inbound_replacement_review(path: &Path, recovery_leaf: Option<&str>) -> ReviewItem {
    let recovery = recovery_leaf
        .map(|leaf| format!(" The prior local body remains beside it as {leaf}."))
        .unwrap_or_default();
    ReviewItem {
        id: format!("inbound-replacement-race:{}", path.display()),
        kind: ReviewKind::ContentConflict,
        relative_path: path.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary: format!(
            "Drive downloaded and hash-verified a newer body, but could not safely complete its replacement. No further overwrite was attempted.{recovery} Inspect the local path and recheck before resolving this review."
        ),
        actions: vec![ReviewAction::OpenConflictCopies],
    }
}

#[cfg(test)]
pub(super) fn publish_staged_download(
    root: &Path,
    relative_path: &Path,
    destination: &Path,
    staged: &Path,
    precondition: &DownloadPrecondition,
    destination_boundary: &shellx_drive_desktop_core::LocalOperationBoundary,
) -> CoreResult<DownloadPublication> {
    let verified = VerifiedStagedFile(
        fs::OpenOptions::new()
            .read(true)
            .access_mode(
                windows_sys::Win32::Storage::FileSystem::DELETE
                    | windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES,
            )
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(staged)?,
    );
    let mut local_read_budget = local_read_budget_for_sync_pass();
    publish_staged_download_with_budget(
        root,
        relative_path,
        destination,
        staged,
        &verified,
        precondition,
        destination_boundary,
        &mut local_read_budget,
        None,
    )
}

// Keep every frozen-path witness and budget explicit at this security boundary;
// grouping them would make it easier to accidentally reuse a stale witness.
#[allow(clippy::too_many_arguments)]
pub(super) fn publish_staged_download_with_budget(
    root: &Path,
    relative_path: &Path,
    destination: &Path,
    staged: &Path,
    verified: &VerifiedStagedFile,
    precondition: &DownloadPrecondition,
    destination_boundary: &shellx_drive_desktop_core::LocalOperationBoundary,
    local_read_budget: &mut ReadBudget,
    staging: Option<(&OwnedStagingRoot, &Path)>,
) -> CoreResult<DownloadPublication> {
    if verify_local_operation_boundary(destination_boundary).is_err() {
        return Ok(DownloadPublication::NeedsReview {
            review: download_race_review(relative_path),
        });
    }
    let current = current_local_entry_with_budget(root, relative_path, local_read_budget)?;
    if !download_precondition_matches(precondition, current.as_ref()) {
        return Ok(DownloadPublication::NeedsReview {
            review: download_race_review(relative_path),
        });
    }
    ensure_local_operation_boundary(root, destination)?;
    ensure_tree_has_no_links(staged.parent().ok_or_else(|| {
        DesktopError::UnsafePath("staged download has no private batch parent".to_string())
    })?)?;

    let disposition = download_publication_disposition(precondition, current.as_ref());
    if matches!(
        disposition,
        DownloadPublicationDisposition::NeedsReviewWithoutMutation
    ) {
        return Ok(DownloadPublication::NeedsReview {
            review: download_race_review(relative_path),
        });
    }

    if matches!(
        disposition,
        DownloadPublicationDisposition::PublishReplacing
    ) {
        let frozen =
            match FrozenDestination::open(root, destination, relative_path, local_read_budget) {
                Ok(frozen) if download_precondition_matches(precondition, Some(frozen.entry())) => {
                    frozen
                }
                Ok(_) | Err(_) => {
                    return Ok(DownloadPublication::NeedsReview {
                        review: inbound_replacement_review(relative_path, None),
                    });
                }
            };
        return match publish_replacing_staged_file(
            root,
            destination,
            staged,
            verified,
            staging,
            frozen,
            || Ok(()),
            || Ok(()),
        ) {
            Ok(ReplacementOutcome::Published) => Ok(DownloadPublication::Published),
            Ok(ReplacementOutcome::NeedsReview { recovery_leaf }) => {
                Ok(DownloadPublication::NeedsReview {
                    review: inbound_replacement_review(relative_path, recovery_leaf.as_deref()),
                })
            }
            Err(_) => Ok(DownloadPublication::NeedsReview {
                review: inbound_replacement_review(relative_path, None),
            }),
        };
    }

    let staged_parent = staged.parent().ok_or_else(|| {
        DesktopError::UnsafePath("staged download has no private batch parent".to_string())
    })?;
    let publish = || {
        let current = current_local_entry_with_budget(root, relative_path, local_read_budget)?;
        if !download_precondition_matches(precondition, current.as_ref()) {
            return Err(DesktopError::InvalidState(
                "local destination changed before the native publication".to_string(),
            ));
        }
        Ok(())
    };
    match move_verified_staged_file(
        staged_parent,
        staged,
        verified,
        destination,
        root,
        false,
        publish,
    ) {
        Ok(()) => Ok(DownloadPublication::Published),
        Err(_) => Ok(DownloadPublication::NeedsReview {
            review: download_race_review(relative_path),
        }),
    }
}

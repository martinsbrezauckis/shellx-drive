//! User-visible, recoverable macOS terminal-sync reviews.

use std::path::Path;

use crate::platform::unix::filesystem::ReplacingPublication;
use shellx_drive_desktop_core::{ReviewAction, ReviewItem, ReviewKind};

pub(super) fn needs_review() -> ReplacingPublication {
    ReplacingPublication::NeedsReview {
        recovery_leaf: None,
    }
}

pub(super) fn move_review(
    path: &Path,
    summary: &str,
    is_directory: bool,
    descendant_count: usize,
) -> ReviewItem {
    ReviewItem {
        id: format!("macos-move-review:{}", path.display()),
        kind: ReviewKind::PathConflict,
        relative_path: path.to_path_buf(),
        descendant_count,
        is_directory,
        summary: summary.to_string(),
        actions: vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    }
}

pub(super) fn conflict_review(id: &str, path: &Path) -> ReviewItem {
    ReviewItem {
        id: format!("macos-replacement-conflict:{id}"),
        kind: ReviewKind::ContentConflict,
        relative_path: path.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary: "Drive kept a newer version. The local replacement was left untouched for review."
            .to_string(),
        actions: vec![ReviewAction::OpenConflictCopies],
    }
}

pub(super) fn unsupported_review(id: &str, path: &Path, _: u64) -> ReviewItem {
    ReviewItem {
        id: format!("macos-replacement-unsupported:{id}"), kind: ReviewKind::UnsupportedTransfer,
        relative_path: path.to_path_buf(), descendant_count: 0, is_directory: false,
        summary: "Drive does not support this safe replacement upload yet. Both copies were left untouched.".to_string(),
        actions: vec![ReviewAction::RetryWhenServerSupportsResumableReplacement],
    }
}

pub(super) fn replacement_review(path: &Path, retained_batch: Option<&Path>) -> ReviewItem {
    let summary = retained_batch.map_or_else(
        || "Drive or local state changed before publication. The local destination was left untouched; the downloaded body was discarded and sync can retry after recheck.".to_string(),
        |batch| format!("Drive downloaded and verified a newer body but its local replacement needs review. Inspect the retained private recovery batch at {}.", batch.display()),
    );
    ReviewItem {
        id: format!("macos-inbound-replacement:{}", path.display()),
        kind: ReviewKind::ContentConflict,
        relative_path: path.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary,
        actions: vec![ReviewAction::OpenConflictCopies],
    }
}

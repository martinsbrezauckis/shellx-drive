//! Deterministic keep-both paths and pending conflict-review continuity.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::{
    mirror::{ReconcilePlan, SyncAction},
    model::{ReviewItem, ReviewKind},
};

pub(crate) fn content_conflict_review_id(local_path: &Path) -> String {
    format!("{:?}:{}", ReviewKind::ContentConflict, local_path.display())
}

pub(crate) fn stabilize_pending_content_conflicts(
    plan: &mut ReconcilePlan,
    pending: &[ReviewItem],
) {
    for action in &mut plan.actions {
        let SyncAction::WriteRemoteConflictCopy {
            local_path,
            conflict_path,
            ..
        } = action
        else {
            continue;
        };
        let id = content_conflict_review_id(local_path);
        let Some(existing) = pending.iter().find(|item| {
            item.kind == ReviewKind::ContentConflict
                && item.id == id
                && is_conflict_copy_path_for(local_path, &item.relative_path)
        }) else {
            continue;
        };
        let generated_path = conflict_path.clone();
        *conflict_path = existing.relative_path.clone();
        if let Some(review) = plan.reviews.iter_mut().find(|item| {
            item.kind == ReviewKind::ContentConflict
                && item.id == id
                && item.relative_path == generated_path
        }) {
            *review = existing.clone();
        }
    }
}

fn is_conflict_copy_path_for(local_path: &Path, candidate: &Path) -> bool {
    if candidate.parent() != local_path.parent() {
        return false;
    }
    let local_name = match local_path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => return false,
    };
    let candidate_name = match candidate.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => return false,
    };
    let (stem, extension) = match local_name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() && !extension.is_empty() => {
            (stem, Some(extension))
        }
        _ => (local_name, None),
    };
    let prefix = format!("{stem} (Drive conflict ");
    let suffix = extension
        .map(|extension| format!(").{extension}"))
        .unwrap_or_else(|| ")".to_string());
    let Some(timestamp) = candidate_name
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix(&suffix))
    else {
        return false;
    };
    chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H%M%S").is_ok()
}

/// Nextcloud-style keep-both conflict label: `report (Drive conflict
/// 2026-08-12 173045).pdf`, preserving a final extension when there is one.
pub fn conflict_copy_path(path: &Path, now: DateTime<Utc>) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Drive file");
    let (stem, extension) = match file_name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() && !extension.is_empty() => {
            (stem, Some(extension))
        }
        _ => (file_name, None),
    };
    let timestamp = now.format("%Y-%m-%d %H%M%S");
    let conflict = match extension {
        Some(extension) => format!("{stem} (Drive conflict {timestamp}).{extension}"),
        None => format!("{stem} (Drive conflict {timestamp})"),
    };
    parent.join(conflict)
}

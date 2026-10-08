use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
};

use crate::{
    conflicts::{conflict_copy_path, content_conflict_review_id},
    inspect_local_tree, inspect_remote_paths, map_remote_paths, BaselineEntry, DesktopError,
    RemotePathIssue, Result, ReviewAction, ReviewItem, ReviewKind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Bodies at or below this size may use the existing server's bounded
/// `PUT /files/{id}/content` contract. Larger replacement bodies are not sent
/// until Drive provides a resumable existing-file-update endpoint.
pub const SIMPLE_EXISTING_REPLACEMENT_LIMIT: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteEntryKind {
    File,
    Folder,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteEntry {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: RemoteEntryKind,
    pub revision: i64,
    pub content_hash: Option<String>,
    pub size_bytes: Option<u64>,
    pub trashed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEntry {
    pub relative_path: PathBuf,
    pub content_hash: Option<String>,
    pub size_bytes: u64,
    pub is_directory: bool,
    /// Filled by the native shell for directories scanned from a checked,
    /// non-link handle. The core never guesses it from a path or contents.
    pub directory_identity: Option<crate::DirectoryIdentity>,
}

/// A local item whose name cannot safely participate in a Windows v0.1 sync.
/// The scanner records it without uploading or renaming anything so the
/// desktop shell can persist an exact Needs review item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPathIssue {
    pub path: PathBuf,
    pub reason: String,
}

/// The non-mutating local tree inspection used by sync planning.  Strict
/// execution and recovery code may continue to call `scan_local_tree`, which
/// rejects any issue before it can alter the filesystem.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalTreeInspection {
    pub entries: Vec<LocalEntry>,
    pub issues: Vec<LocalPathIssue>,
}

/// The exact local row observed when a remote file download was planned.
/// Publication rechecks this after the network await; a changed row never
/// authorizes an overwrite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DownloadPrecondition {
    Absent,
    ExactLocal {
        content_hash: Option<String>,
        size_bytes: u64,
        is_directory: bool,
    },
}

impl DownloadPrecondition {
    pub fn observed(local: Option<&LocalEntry>) -> Self {
        match local {
            None => Self::Absent,
            Some(local) => Self::ExactLocal {
                content_hash: local.content_hash.clone(),
                size_bytes: local.size_bytes,
                is_directory: local.is_directory,
            },
        }
    }
}

/// Pure comparison seam used both by the executor and race regressions. The
/// path itself is carried by the caller; this binds the item kind, bytes, and
/// size that were present at plan time.
pub fn download_precondition_matches(
    expected: &DownloadPrecondition,
    current: Option<&LocalEntry>,
) -> bool {
    match (expected, current) {
        (DownloadPrecondition::Absent, None) => true,
        (
            DownloadPrecondition::ExactLocal {
                content_hash,
                size_bytes,
                is_directory,
            },
            Some(current),
        ) => {
            current.content_hash == *content_hash
                && current.size_bytes == *size_bytes
                && current.is_directory == *is_directory
        }
        _ => false,
    }
}

/// An upload can only use the immutable snapshot made by the native shell if
/// it is still the exact regular-file row that reconciliation planned. This
/// binds the body snapshot to its planned path, hash, size, and kind before
/// any remote mutation begins.
pub fn upload_precondition_matches(planned: &LocalEntry, snapshot: &LocalEntry) -> bool {
    planned.relative_path == snapshot.relative_path
        && planned.content_hash == snapshot.content_hash
        && planned.size_bytes == snapshot.size_bytes
        && planned.is_directory == snapshot.is_directory
}

/// The executor selects a native publication primitive only after its
/// planned local entry still exactly matches. New files use a non-replacing
/// move; an unchanged tracked file uses `ReplaceFileW` without a backup name.
/// Any failed boundary check or native call becomes a review instead of a
/// best-effort retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DownloadPublicationDisposition {
    PublishNonReplacing,
    PublishReplacing,
    NeedsReviewWithoutMutation,
}

/// The root-only proof carried by a planned folder rename/move. The directory
/// identity is the sole proof that an outbound directory is the saved object;
/// the saved subtree rows are a separate execution precondition so a native
/// inbound move never carries a local edit, omission, or extra child.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderMovePrecondition {
    pub identity: crate::DirectoryIdentity,
    pub entries: BTreeMap<PathBuf, FolderMoveEntry>,
    /// Remote subtree witness for an inbound root move. The native executor
    /// refetches and compares it immediately before and after its handle-bound
    /// native rename; Drive has no server-side subtree lease in v0.1.
    pub remote_witness: Option<FolderRemoteWitness>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderMoveEntry {
    pub content_hash: Option<String>,
    pub is_directory: bool,
    /// Every saved directory must retain its own handle identity. This blocks
    /// a delete-and-recreate child directory from inheriting an old remote
    /// child ID merely because the path and empty-folder shape still match.
    pub directory_identity: Option<crate::DirectoryIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderRemoteWitness {
    /// The selected Drive root and every ancestor through the workspace root.
    /// This pins the selector's effective Drive location as well as the root
    /// folder's own ID, kind, and revision.
    pub selected_root_ancestry: Option<Vec<FolderRemoteWitnessNode>>,
    pub root_id: String,
    pub root_path: PathBuf,
    pub entries: BTreeMap<String, FolderRemoteWitnessEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderRemoteWitnessNode {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: RemoteEntryKind,
    pub revision: i64,
    pub content_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderRemoteWitnessEntry {
    pub parent_id: Option<String>,
    pub relative_path: PathBuf,
    pub kind: RemoteEntryKind,
    pub revision: i64,
    pub content_hash: Option<String>,
}

/// Decide whether it is safe to publish a verified Drive body. This is kept
/// pure so planning/execution tests can prove that an exact baseline body gets
/// a replace-in-place publication without an app-owned recovery backup.
pub fn download_publication_disposition(
    expected: &DownloadPrecondition,
    current: Option<&LocalEntry>,
) -> DownloadPublicationDisposition {
    if !download_precondition_matches(expected, current) {
        return DownloadPublicationDisposition::NeedsReviewWithoutMutation;
    }
    match expected {
        DownloadPrecondition::Absent => DownloadPublicationDisposition::PublishNonReplacing,
        DownloadPrecondition::ExactLocal { .. } => DownloadPublicationDisposition::PublishReplacing,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncAction {
    EnsureLocalDirectory {
        remote_id: String,
        relative_path: PathBuf,
    },
    Download {
        remote_id: String,
        relative_path: PathBuf,
        revision: i64,
        precondition: DownloadPrecondition,
    },
    UploadNew {
        relative_path: PathBuf,
        is_directory: bool,
        local: LocalEntry,
    },
    UploadExisting {
        remote_id: String,
        relative_path: PathBuf,
        base_revision: i64,
        local: LocalEntry,
    },
    MoveLocal {
        remote_id: String,
        from: PathBuf,
        to: PathBuf,
        precondition: DownloadPrecondition,
        folder_precondition: Option<FolderMovePrecondition>,
    },
    MoveRemote {
        remote_id: String,
        from: PathBuf,
        to: PathBuf,
        base_revision: i64,
        folder_precondition: Option<FolderMovePrecondition>,
    },
    WriteRemoteConflictCopy {
        remote_id: String,
        local_path: PathBuf,
        conflict_path: PathBuf,
    },
}

#[derive(Clone, Debug, Default)]
pub struct ReconcilePlan {
    pub actions: Vec<SyncAction>,
    pub reviews: Vec<ReviewItem>,
    pub remote_paths: BTreeMap<String, PathBuf>,
}

impl ReconcilePlan {
    pub fn requires_transfer(&self) -> bool {
        !self.actions.is_empty()
    }
}

/// Convert locally discovered Windows-name incompatibilities into an
/// all-or-nothing compatibility plan.  Discarding any independently planned
/// action is intentional: a mixed manifest/local set must not partially sync
/// while a user-visible path review is unresolved.
pub fn apply_local_path_compatibility_reviews(
    mut plan: ReconcilePlan,
    issues: &[LocalPathIssue],
) -> ReconcilePlan {
    if issues.is_empty() {
        return plan;
    }
    let mut unsafe_folder_moves = BTreeMap::<PathBuf, (PathBuf, usize)>::new();
    for action in &plan.actions {
        let (from, to, precondition) = match action {
            SyncAction::MoveLocal {
                from,
                to,
                folder_precondition: Some(precondition),
                ..
            }
            | SyncAction::MoveRemote {
                from,
                to,
                folder_precondition: Some(precondition),
                ..
            } => (from, to, precondition),
            _ => continue,
        };
        if issues
            .iter()
            .any(|issue| issue.path.starts_with(from) || issue.path.starts_with(to))
        {
            unsafe_folder_moves.insert(
                from.clone(),
                (to.clone(), precondition.entries.len().saturating_sub(1)),
            );
        }
    }
    if !unsafe_folder_moves.is_empty() {
        // A reparse/unsafe child beneath a planned root is an unsafe boundary,
        // not an independently uploadable item. Return one persistent root
        // review and no descendant action.
        plan.actions.clear();
        plan.reviews.clear();
        plan.reviews.extend(unsafe_folder_moves.into_iter().map(
            |(from, (to, descendant_count))| ReviewItem {
                id: format!("folder-move-unsafe-path:{}:{}", from.display(), to.display()),
                kind: ReviewKind::UnsafeLink,
                relative_path: from,
                descendant_count,
                is_directory: true,
                summary: "A planned folder move contains a symbolic link, reparse point, or incompatible local path. Nothing in the subtree was moved, uploaded, downloaded, or overwritten; remove the unsafe item and recheck.".to_string(),
                actions: vec![ReviewAction::RenameLocalCopy, ReviewAction::OpenConflictCopies],
            },
        ));
        return plan;
    }
    // The planner may already have reserved a folder root because a scanner
    // excluded an unsafe descendant from its exact subtree comparison. Avoid
    // splitting that root decision into an additional child-path review.
    let covered = |issue: &LocalPathIssue| {
        plan.reviews
            .iter()
            .any(|review| review.is_directory && issue.path.starts_with(&review.relative_path))
    };
    let remaining = issues
        .iter()
        .filter(|issue| !covered(issue))
        .collect::<Vec<_>>();
    if remaining.is_empty() {
        return plan;
    }
    plan.actions.clear();
    plan.reviews.extend(remaining.into_iter().map(|issue| ReviewItem {
        id: format!("local-path:{}", issue.path.display()),
        kind: ReviewKind::UnsafePath,
        relative_path: issue.path.clone(),
        descendant_count: 0,
        is_directory: false,
        summary: format!(
            "Local path cannot be synced safely on Windows because {}. No local files were uploaded or renamed; rename or remove the incompatible local item, then recheck.",
            issue.reason
        ),
        actions: Vec::new(),
    }));
    plan.reviews.sort_by(|left, right| {
        (&left.relative_path, &left.summary, &left.id).cmp(&(
            &right.relative_path,
            &right.summary,
            &right.id,
        ))
    });
    plan
}

/// Strict local scan for recovery and final mutation preconditions.  The
/// planning surface calls `inspect_local_tree` instead so local incompatibility
/// can persist as Needs review rather than a generic desktop Error.
pub fn scan_local_tree(root: &Path) -> Result<Vec<LocalEntry>> {
    let inspection = inspect_local_tree(root)?;
    let Some(issue) = inspection.issues.first() else {
        return Ok(inspection.entries);
    };
    Err(DesktopError::UnsafePath(format!(
        "{}: {}",
        issue.path.display(),
        issue.reason
    )))
}

/// Ensure the on-disk subtree about to be moved to recovery is still exactly
/// the reviewed baseline. A recovery move is reversible, but it must never
/// hide a local edit made after the user first saw the deletion review.
pub fn reviewed_local_subtree_matches_baseline(
    item: &ReviewItem,
    baseline: &BTreeMap<String, BaselineEntry>,
    local: &[LocalEntry],
) -> Result<()> {
    let expected = baseline
        .values()
        .filter(|entry| {
            entry.relative_path == item.relative_path
                || entry.relative_path.starts_with(&item.relative_path)
        })
        .map(|entry| (entry.relative_path.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    if expected.is_empty() {
        return Err(DesktopError::InvalidState(
            "the recovery review has no saved local baseline".to_string(),
        ));
    }
    if expected.len().saturating_sub(1) != item.descendant_count {
        return Err(DesktopError::InvalidState(
            "the saved recovery baseline no longer matches the review impact".to_string(),
        ));
    }

    let actual = local
        .iter()
        .filter(|entry| {
            entry.relative_path == item.relative_path
                || entry.relative_path.starts_with(&item.relative_path)
        })
        .map(|entry| (entry.relative_path.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    if actual.len() != expected.len() {
        return Err(DesktopError::InvalidState(
            "the reviewed local subtree changed after confirmation; it was left in place"
                .to_string(),
        ));
    }

    for (path, saved) in expected {
        let current = actual.get(&path).ok_or_else(|| {
            DesktopError::InvalidState(
                "the reviewed local subtree changed after confirmation; it was left in place"
                    .to_string(),
            )
        })?;
        let saved_is_directory = match saved.kind.as_str() {
            "folder" => true,
            "file" => false,
            _ => {
                return Err(DesktopError::InvalidState(
                    "the saved recovery baseline has an unknown item kind".to_string(),
                ));
            }
        };
        if current.is_directory != saved_is_directory
            || (!saved_is_directory && current.content_hash != saved.content_hash)
            || (saved_is_directory
                && saved.directory_identity.is_some()
                && current.directory_identity != saved.directory_identity)
        {
            return Err(DesktopError::InvalidState(format!(
                "the reviewed local item changed after confirmation and was left in place: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Before a reviewed whole-subtree mutation, prove that the complete current
/// subtree is still the exact saved baseline. An added, moved, or modified
/// descendant must stop the operation rather than silently carrying unrelated
/// current work into a restore or recursive trash action.
pub fn reviewed_remote_subtree_matches_baseline(
    item: &ReviewItem,
    baseline: &BTreeMap<String, BaselineEntry>,
    selected_remote_root: Option<&str>,
    remote: &[RemoteEntry],
) -> Result<()> {
    let paths = map_remote_paths(remote, selected_remote_root)?;
    let expected = baseline
        .values()
        .filter(|entry| {
            entry.relative_path == item.relative_path
                || entry.relative_path.starts_with(&item.relative_path)
        })
        .map(|entry| (entry.remote_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    if expected.is_empty() || expected.len().saturating_sub(1) != item.descendant_count {
        return Err(DesktopError::InvalidState(
            "the saved Drive subtree no longer matches the reviewed descendant impact".to_string(),
        ));
    }

    let live =
        remote
            .iter()
            .filter(|entry| !entry.trashed)
            .filter_map(|entry| {
                paths.get(&entry.id).and_then(|path| {
                    (path == &item.relative_path || path.starts_with(&item.relative_path))
                        .then_some((entry.id.as_str(), entry, path))
                })
            })
            .collect::<Vec<_>>();
    if live.len() != expected.len() {
        return Err(DesktopError::InvalidState(
            "Drive added or removed a reviewed descendant; no reviewed subtree mutation was attempted"
                .to_string(),
        ));
    }
    for (id, entry, path) in live {
        let saved = expected.get(id).ok_or_else(|| {
            DesktopError::InvalidState(
                "Drive added a reviewed descendant; no reviewed subtree mutation was attempted"
                    .to_string(),
            )
        })?;
        let saved_kind = if saved.kind.eq_ignore_ascii_case("folder") {
            RemoteEntryKind::Folder
        } else if saved.kind.eq_ignore_ascii_case("file") {
            RemoteEntryKind::File
        } else {
            return Err(DesktopError::InvalidState(
                "the saved Drive subtree has an unknown item kind".to_string(),
            ));
        };
        if entry.parent_id.as_deref() != saved.parent_id.as_deref()
            || entry.kind != saved_kind
            || entry.revision != saved.revision
            || entry.content_hash != saved.content_hash
            || path != &saved.relative_path
        {
            return Err(DesktopError::InvalidState(format!(
                "Drive changed a reviewed descendant; no reviewed subtree mutation was attempted: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Compare one local scan, one remote manifest, and the last persisted common
/// ancestor. It plans every mutation but deliberately never performs a delete.
pub fn plan_reconciliation(
    baseline: &BTreeMap<String, BaselineEntry>,
    selected_remote_root: Option<&str>,
    remote_entries: &[RemoteEntry],
    local_entries: &[LocalEntry],
    now: DateTime<Utc>,
) -> Result<ReconcilePlan> {
    let mapping = inspect_remote_paths(remote_entries, selected_remote_root)?;
    if !mapping.issues.is_empty() {
        // A manifest incompatibility is never partially applied.  Retaining
        // zero actions makes both a new sync and a review recheck pure with
        // respect to the selected local root; the caller persists only the
        // review state and waits for a compatible Drive manifest.
        return Ok(ReconcilePlan {
            actions: Vec::new(),
            reviews: mapping
                .issues
                .iter()
                .map(remote_path_compatibility_review)
                .collect(),
            remote_paths: mapping.paths,
        });
    }
    let live_remote_paths = mapping.paths;
    let remote_by_id = remote_entries
        .iter()
        .filter(|entry| !entry.trashed && live_remote_paths.contains_key(&entry.id))
        .map(|entry| (entry.id.as_str(), entry))
        // The plan is user-visible, so do not let a randomized hash-map
        // iteration choose which same-hash candidate is considered first.
        .collect::<BTreeMap<_, _>>();
    let all_live_remote_by_id = remote_entries
        .iter()
        .filter(|entry| !entry.trashed)
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut plan = ReconcilePlan {
        actions: Vec::new(),
        reviews: Vec::new(),
        remote_paths: live_remote_paths.clone(),
    };
    let folder_moves = plan_identity_folder_moves(
        baseline,
        selected_remote_root,
        &remote_by_id,
        &all_live_remote_by_id,
        &live_remote_paths,
        local_entries,
        &mut plan,
    );
    let remote_paths = folder_moves.effective_remote_paths;
    plan.remote_paths = remote_paths.clone();
    let local_by_path =
        effective_local_entries(local_entries, &folder_moves.pending_inbound_transforms);
    let mut claimed_local_paths = folder_moves.claimed_local_paths;
    let contained_remote_ids = folder_moves.contained_remote_ids;
    let contained_baseline_ids = folder_moves.contained_baseline_ids;
    let effective_baseline_paths = folder_moves.effective_baseline_paths;

    // Reserve every unchanged exact common ancestor before any rename search.
    // Without this preclaim, a missing A can bind to unchanged B simply
    // because B has the same hash (or a folder's `None` hash).
    for (remote_id, remote) in &remote_by_id {
        let Some(common) = baseline.get(*remote_id) else {
            continue;
        };
        let common_path = effective_baseline_paths
            .get(*remote_id)
            .unwrap_or(&common.relative_path);
        let path = remote_paths
            .get(*remote_id)
            .expect("remote path membership was filtered");
        let remote_unchanged = remote.revision == common.revision
            && remote.content_hash == common.content_hash
            && path == common_path;
        if remote_unchanged
            && local_by_path
                .get(common_path.as_path())
                .is_some_and(|local| same_baseline_and_local(common, local))
        {
            claimed_local_paths.insert(common_path.clone());
        }
    }

    for (remote_id, remote) in &remote_by_id {
        if contained_remote_ids.contains(*remote_id) {
            continue;
        }
        let path = remote_paths
            .get(*remote_id)
            .expect("remote path membership was filtered")
            .clone();
        let Some(common) = baseline.get(*remote_id) else {
            if let Some(existing) = local_by_path.get(path.as_path()).copied() {
                // A Drive object that predates the local baseline must never
                // publish over an ordinary local file. Equal object/body pairs
                // are safe to adopt on the next persisted baseline; every other
                // collision waits for a named human decision.
                claimed_local_paths.insert(path.clone());
                if !same_remote_and_local(remote, existing) {
                    plan.reviews.push(new_remote_collision_review(&path));
                }
            } else if remote.kind == RemoteEntryKind::Folder {
                plan.actions.push(SyncAction::EnsureLocalDirectory {
                    remote_id: (*remote_id).to_string(),
                    relative_path: path,
                });
            } else {
                plan.actions.push(SyncAction::Download {
                    remote_id: (*remote_id).to_string(),
                    relative_path: path,
                    revision: remote.revision,
                    precondition: DownloadPrecondition::Absent,
                });
            }
            continue;
        };
        let common_path = effective_baseline_paths
            .get(*remote_id)
            .unwrap_or(&common.relative_path);
        claimed_local_paths.insert(common_path.clone());
        let local = local_by_path.get(common_path.as_path()).copied();
        let remote_changed = remote.revision != common.revision
            || remote.content_hash != common.content_hash
            || path != *common_path;

        match local {
            None => {
                let rename_candidates = unique_file_rename_candidates(
                    common,
                    local_entries,
                    &claimed_local_paths,
                    baseline,
                    &remote_by_id,
                );
                if rename_candidates.len() == 1 {
                    let renamed = rename_candidates[0];
                    claimed_local_paths.insert(renamed.relative_path.clone());
                    // A prior inbound file move can complete before its body
                    // download. Its next planning pass still has the old
                    // baseline, but the exact baseline body now sits at the
                    // current remote path. Resume the verified body download
                    // there instead of turning a recoverable interruption into
                    // a permanent path conflict.
                    let resumed_inbound_move = common.kind.eq_ignore_ascii_case("file")
                        && remote.kind == RemoteEntryKind::File
                        && renamed.relative_path == path
                        && same_baseline_and_local(common, renamed);
                    if resumed_inbound_move {
                        if remote.content_hash != common.content_hash {
                            plan.actions.push(SyncAction::Download {
                                remote_id: (*remote_id).to_string(),
                                relative_path: path,
                                revision: remote.revision,
                                precondition: DownloadPrecondition::observed(Some(renamed)),
                            });
                        }
                    } else if remote_changed {
                        plan.reviews
                            .push(path_conflict_review(&renamed.relative_path));
                    } else {
                        plan.actions.push(SyncAction::MoveRemote {
                            remote_id: (*remote_id).to_string(),
                            from: common_path.clone(),
                            to: renamed.relative_path.clone(),
                            base_revision: common.revision,
                            folder_precondition: None,
                        });
                    }
                } else if rename_candidates.len() > 1 {
                    // The candidate file identity is ambiguous. Reserve all
                    // candidates so the final untracked pass cannot upload a
                    // possibly renamed baseline object while its decision is
                    // still pending.
                    for candidate in rename_candidates {
                        claimed_local_paths.insert(candidate.relative_path.clone());
                    }
                    plan.reviews.push(path_conflict_review(common_path));
                } else if remote_changed {
                    plan.reviews.push(delete_edit_review(
                        "local deletion raced with a Drive change",
                        common_path,
                    ));
                } else {
                    plan.reviews.push(local_deletion_review(
                        common_path,
                        baseline_descendants(common_path, baseline),
                        common.kind.eq_ignore_ascii_case("folder"),
                    ));
                }
            }
            Some(local) => {
                let local_changed = !same_baseline_and_local(common, local);
                if path != *common_path {
                    // Folder rows have no body identity. Do not infer that a
                    // whole local subtree is unchanged merely because its
                    // folder row has the same `None` hash.
                    let is_unchanged_file = !local_changed
                        && common.kind.eq_ignore_ascii_case("file")
                        && remote.kind == RemoteEntryKind::File;
                    if local_by_path.contains_key(path.as_path()) || !is_unchanged_file {
                        plan.reviews.push(path_conflict_review(common_path));
                    } else {
                        plan.actions.push(SyncAction::MoveLocal {
                            remote_id: (*remote_id).to_string(),
                            from: common_path.clone(),
                            to: path.clone(),
                            precondition: DownloadPrecondition::observed(Some(local)),
                            folder_precondition: None,
                        });
                        // A remote move can arrive with a changed body. Move
                        // the known baseline file first, then require that
                        // exact body before the replacement at its new path.
                        // This preserves a single local copy and keeps both
                        // mutations independently atomic.
                        if remote.content_hash != common.content_hash {
                            plan.actions.push(SyncAction::Download {
                                remote_id: (*remote_id).to_string(),
                                relative_path: path,
                                revision: remote.revision,
                                precondition: DownloadPrecondition::observed(Some(local)),
                            });
                        }
                    }
                    continue;
                }
                if local_changed && remote_changed {
                    if local.content_hash == remote.content_hash {
                        continue;
                    }
                    let conflict_path = conflict_copy_path(common_path, now);
                    plan.actions.push(SyncAction::WriteRemoteConflictCopy {
                        remote_id: (*remote_id).to_string(),
                        local_path: common_path.clone(),
                        conflict_path: conflict_path.clone(),
                    });
                    plan.reviews
                        .push(content_conflict_review(common_path, &conflict_path));
                } else if local_changed {
                    if !local.is_directory {
                        plan.actions.push(SyncAction::UploadExisting {
                            remote_id: (*remote_id).to_string(),
                            relative_path: common_path.clone(),
                            base_revision: common.revision,
                            local: local.clone(),
                        });
                    }
                } else if remote_changed {
                    if remote.kind == RemoteEntryKind::Folder {
                        plan.actions.push(SyncAction::EnsureLocalDirectory {
                            remote_id: (*remote_id).to_string(),
                            relative_path: common_path.clone(),
                        });
                    } else {
                        plan.actions.push(SyncAction::Download {
                            remote_id: (*remote_id).to_string(),
                            relative_path: common_path.clone(),
                            revision: remote.revision,
                            precondition: DownloadPrecondition::observed(Some(local)),
                        });
                    }
                }
            }
        }
    }

    // A tracked remote item disappearing from the manifest is a remote delete,
    // which cannot remove a local path until the user accepts the review item.
    for (remote_id, common) in baseline {
        if contained_baseline_ids.contains(remote_id) {
            continue;
        }
        if remote_by_id.contains_key(remote_id.as_str()) {
            continue;
        }
        let common_path = effective_baseline_paths
            .get(remote_id.as_str())
            .unwrap_or(&common.relative_path);
        // Claim the common path before the final local-create pass. Otherwise a
        // remote delete could be planned both as a review and as UploadNew,
        // silently resurrecting the remote object after the review.
        claimed_local_paths.insert(common_path.clone());
        if let Some(local) = local_by_path.get(common_path.as_path()) {
            if local.content_hash != common.content_hash {
                plan.reviews.push(delete_edit_review(
                    "Drive deletion raced with a local change",
                    common_path,
                ));
            } else {
                plan.reviews.push(remote_deletion_review(
                    common_path,
                    descendants(common_path, local_entries),
                ));
            }
        } else if let Some(renamed) = local_entries.iter().find(|candidate| {
            !claimed_local_paths.contains(&candidate.relative_path)
                && same_baseline_and_local(common, candidate)
        }) {
            // A local rename is itself a local change. A concurrent remote
            // deletion cannot turn it into an untracked upload; preserve it as
            // a delete/edit review until the user chooses the recovery path.
            claimed_local_paths.insert(renamed.relative_path.clone());
            plan.reviews.push(delete_edit_review(
                "Drive deletion raced with a local rename",
                &renamed.relative_path,
            ));
        }
    }

    // Anything ordinary in the local folder which was not part of a persisted
    // baseline is a local create. It is planned for upload, not silently
    // discarded or treated as a delete.
    for local in local_entries {
        if claimed_local_paths.contains(&local.relative_path)
            || remote_paths
                .values()
                .any(|path| path == &local.relative_path)
        {
            continue;
        }
        plan.actions.push(SyncAction::UploadNew {
            relative_path: local.relative_path.clone(),
            is_directory: local.is_directory,
            local: local.clone(),
        });
    }
    Ok(plan)
}

fn same_remote_and_local(remote: &RemoteEntry, local: &LocalEntry) -> bool {
    matches!(
        (&remote.kind, local.is_directory),
        (RemoteEntryKind::Folder, true) | (RemoteEntryKind::File, false)
    ) && (local.is_directory || local.content_hash == remote.content_hash)
}

/// Planning output for directory-identity moves. Effective paths allow the
/// ordinary child reconciliation to continue at the post-move location, but
/// only the root metadata/native move is ever emitted.
struct FolderMovePlanning {
    effective_remote_paths: BTreeMap<String, PathBuf>,
    effective_baseline_paths: BTreeMap<String, PathBuf>,
    pending_inbound_transforms: Vec<(PathBuf, PathBuf)>,
    claimed_local_paths: HashSet<PathBuf>,
    contained_remote_ids: HashSet<String>,
    contained_baseline_ids: HashSet<String>,
}

fn plan_identity_folder_moves(
    baseline: &BTreeMap<String, BaselineEntry>,
    selected_remote_root: Option<&str>,
    remote_by_id: &BTreeMap<&str, &RemoteEntry>,
    all_live_remote_by_id: &BTreeMap<&str, &RemoteEntry>,
    live_remote_paths: &BTreeMap<String, PathBuf>,
    local_entries: &[LocalEntry],
    plan: &mut ReconcilePlan,
) -> FolderMovePlanning {
    let mut result = FolderMovePlanning {
        effective_remote_paths: live_remote_paths.clone(),
        effective_baseline_paths: BTreeMap::new(),
        pending_inbound_transforms: Vec::new(),
        claimed_local_paths: HashSet::new(),
        contained_remote_ids: HashSet::new(),
        contained_baseline_ids: HashSet::new(),
    };
    let mut folders = baseline
        .iter()
        .filter(|(_, entry)| entry.kind.eq_ignore_ascii_case("folder"))
        .collect::<Vec<_>>();
    folders.sort_by(|(left_id, left), (right_id, right)| {
        left.relative_path
            .components()
            .count()
            .cmp(&right.relative_path.components().count())
            .then_with(|| left.relative_path.cmp(&right.relative_path))
            .then_with(|| left_id.cmp(right_id))
    });

    let mut selected_roots = Vec::<PathBuf>::new();
    for (folder_id, saved_root) in folders {
        if selected_roots
            .iter()
            .any(|root| saved_root.relative_path.starts_with(root))
        {
            continue;
        }
        let Some(remote_root) = remote_by_id.get(folder_id.as_str()) else {
            // The ordinary root remote-deletion branch below owns the one
            // user-visible review. Suppress all saved descendants now so they
            // cannot emit their own reviews or fall through into UploadNew.
            contain_folder_deletion_descendants(
                folder_id,
                baseline,
                live_remote_paths,
                &saved_root.relative_path,
                &mut result,
            );
            selected_roots.push(saved_root.relative_path.clone());
            continue;
        };
        let Some(live_root) = live_remote_paths.get(folder_id) else {
            continue;
        };
        if remote_root.kind != RemoteEntryKind::Folder {
            reserve_folder_identity_review(
                baseline,
                live_remote_paths,
                local_entries,
                &saved_root.relative_path,
                Some(live_root),
                &[],
                &mut result,
                plan,
                "Drive changed the tracked folder kind.",
            );
            selected_roots.push(saved_root.relative_path.clone());
            continue;
        }
        let Some(mut precondition) = folder_move_precondition(baseline, saved_root) else {
            let locally_present = local_entries
                .iter()
                .any(|entry| entry.relative_path == saved_root.relative_path && entry.is_directory);
            // v1 migration stays passive for an unchanged same-path folder.
            // A successful ordinary reconciliation will persist its freshly
            // captured identity. Any path/kind absence change is reviewed,
            // never inferred from names or descendant bodies.
            let possible_roots = possible_folder_relocation_roots(
                folder_id,
                &saved_root.relative_path,
                baseline,
                remote_by_id,
                local_entries,
            );
            if live_root == &saved_root.relative_path
                && (locally_present || possible_roots.is_empty())
            {
                continue;
            }
            reserve_folder_identity_review(
                baseline,
                live_remote_paths,
                local_entries,
                &saved_root.relative_path,
                Some(live_root),
                &possible_roots,
                &mut result,
                plan,
                "The saved folder has no NTFS identity yet; complete an unchanged sync before automatic folder moves are enabled.",
            );
            selected_roots.push(saved_root.relative_path.clone());
            continue;
        };

        let inbound = live_root != &saved_root.relative_path;
        let source = local_entries
            .iter()
            .find(|entry| entry.relative_path == saved_root.relative_path && entry.is_directory);
        let identity_roots = local_directory_identity_roots(local_entries, &precondition.identity);
        if inbound {
            let remote_witness = folder_remote_witness(
                folder_id,
                selected_remote_root,
                remote_by_id,
                all_live_remote_by_id,
                live_remote_paths,
            );
            let remote_shape_matches = remote_folder_subtree_shape_matches(
                baseline,
                remote_by_id,
                live_remote_paths,
                &saved_root.relative_path,
                live_root,
            );
            let source_matches = source.is_some_and(|entry| {
                entry.directory_identity.as_ref() == Some(&precondition.identity)
                    && folder_subtree_matches_precondition(
                        &precondition,
                        &saved_root.relative_path,
                        local_entries,
                    )
            });
            let resumed = identity_roots.as_slice() == [live_root.clone()]
                && source.is_none()
                && !local_entries
                    .iter()
                    .any(|entry| entry.relative_path.starts_with(&saved_root.relative_path))
                && folder_subtree_matches_precondition(&precondition, live_root, local_entries);
            let destination_empty = !local_entries
                .iter()
                .any(|entry| entry.relative_path.starts_with(live_root));
            if remote_root.revision != saved_root.revision
                && remote_shape_matches
                && source_matches
                && destination_empty
                && remote_witness.is_some()
            {
                precondition.remote_witness = remote_witness;
                accept_folder_move_paths(
                    baseline,
                    live_remote_paths,
                    &saved_root.relative_path,
                    live_root,
                    false,
                    &mut result,
                );
                claim_local_subtree(
                    &saved_root.relative_path,
                    local_entries,
                    &mut result.claimed_local_paths,
                );
                result.contained_remote_ids.insert(folder_id.clone());
                result.contained_baseline_ids.insert(folder_id.clone());
                result
                    .pending_inbound_transforms
                    .push((saved_root.relative_path.clone(), live_root.clone()));
                plan.actions.push(SyncAction::MoveLocal {
                    remote_id: folder_id.clone(),
                    from: saved_root.relative_path.clone(),
                    to: live_root.clone(),
                    precondition: DownloadPrecondition::ExactLocal {
                        content_hash: None,
                        size_bytes: 0,
                        is_directory: true,
                    },
                    folder_precondition: Some(precondition),
                });
            } else if remote_root.revision != saved_root.revision && remote_shape_matches && resumed
            {
                // The native root move completed before the prior run stopped.
                // Its stable directory identity still binds the folder; child
                // bytes are reconciled below at the new effective paths.
                accept_folder_move_paths(
                    baseline,
                    live_remote_paths,
                    &saved_root.relative_path,
                    live_root,
                    false,
                    &mut result,
                );
                claim_local_subtree(live_root, local_entries, &mut result.claimed_local_paths);
                result.contained_remote_ids.insert(folder_id.clone());
                result.contained_baseline_ids.insert(folder_id.clone());
            } else {
                reserve_folder_identity_review(
                    baseline,
                    live_remote_paths,
                    local_entries,
                    &saved_root.relative_path,
                    Some(live_root),
                    &identity_roots,
                    &mut result,
                    plan,
                    "The inbound folder move could not prove one unchanged local NTFS directory and an empty safe destination.",
                );
            }
            selected_roots.push(saved_root.relative_path.clone());
            continue;
        }

        let source_matches_identity = source
            .is_some_and(|entry| entry.directory_identity.as_ref() == Some(&precondition.identity));
        if source_matches_identity {
            // An unchanged root remains an ordinary tracked folder. Child
            // updates are planned normally; identity mismatch at the saved
            // path means delete/recreate and must not silently fall through.
            continue;
        }
        let relocation_roots = identity_roots
            .iter()
            .filter(|path| *path != &saved_root.relative_path)
            .cloned()
            .collect::<Vec<_>>();
        let possible_roots = possible_folder_relocation_roots(
            folder_id,
            &saved_root.relative_path,
            baseline,
            remote_by_id,
            local_entries,
        );
        if source.is_none() && relocation_roots.len() == 1 {
            let destination = &relocation_roots[0];
            if remote_root.revision == saved_root.revision
                && folder_subtree_matches_precondition(&precondition, destination, local_entries)
                && outbound_folder_destination_is_safe(
                    live_remote_paths,
                    remote_by_id,
                    folder_id,
                    destination,
                )
            {
                accept_folder_move_paths(
                    baseline,
                    live_remote_paths,
                    &saved_root.relative_path,
                    destination,
                    true,
                    &mut result,
                );
                claim_local_subtree(destination, local_entries, &mut result.claimed_local_paths);
                result.contained_remote_ids.insert(folder_id.clone());
                result.contained_baseline_ids.insert(folder_id.clone());
                plan.actions.push(SyncAction::MoveRemote {
                    remote_id: folder_id.clone(),
                    from: saved_root.relative_path.clone(),
                    to: destination.clone(),
                    base_revision: saved_root.revision,
                    folder_precondition: Some(precondition),
                });
                selected_roots.push(saved_root.relative_path.clone());
                continue;
            }
        }
        // A missing/mismatched saved root may be deletion, copy, or
        // delete-and-recreate. If any plausible destination exists, reserve
        // the full subtree so no child can leak into UploadNew while the user
        // decides. The identity itself is never guessed from bodies.
        if source.is_none() && relocation_roots.is_empty() && possible_roots.is_empty() {
            // This is an ordinary local folder deletion, not an inferred
            // rename. Let the root create its established one LocalDeletion
            // review, but reserve all descendants to prevent duplicate child
            // review/upload resurrection actions.
            contain_folder_deletion_descendants(
                folder_id,
                baseline,
                live_remote_paths,
                &saved_root.relative_path,
                &mut result,
            );
            selected_roots.push(saved_root.relative_path.clone());
            continue;
        }
        let mut review_roots = relocation_roots;
        review_roots.extend(possible_roots);
        review_roots.sort();
        review_roots.dedup();
        reserve_folder_identity_review(
            baseline,
            live_remote_paths,
            local_entries,
            &saved_root.relative_path,
            Some(live_root),
            &review_roots,
            &mut result,
            plan,
            "The local folder path changed but no one-to-one unchanged NTFS directory identity and remote revision proof was available.",
        );
        selected_roots.push(saved_root.relative_path.clone());
    }
    result
}

fn contain_folder_deletion_descendants(
    root_id: &str,
    baseline: &BTreeMap<String, BaselineEntry>,
    live_remote_paths: &BTreeMap<String, PathBuf>,
    root_path: &Path,
    result: &mut FolderMovePlanning,
) {
    for (id, entry) in baseline {
        if id != root_id && entry.relative_path.starts_with(root_path) {
            result.contained_baseline_ids.insert(id.clone());
            result.contained_remote_ids.insert(id.clone());
            result
                .claimed_local_paths
                .insert(entry.relative_path.clone());
        }
    }
    for (id, path) in live_remote_paths {
        if id != root_id && path.starts_with(root_path) {
            result.contained_remote_ids.insert(id.clone());
        }
    }
}

fn folder_move_precondition(
    baseline: &BTreeMap<String, BaselineEntry>,
    root: &BaselineEntry,
) -> Option<FolderMovePrecondition> {
    let identity = root.directory_identity.clone()?;
    let mut entries = BTreeMap::new();
    for saved in baseline
        .values()
        .filter(|entry| entry.relative_path.starts_with(&root.relative_path))
    {
        let tail = saved
            .relative_path
            .strip_prefix(&root.relative_path)
            .ok()?
            .to_path_buf();
        let is_directory = match saved.kind.as_str() {
            "folder" => true,
            "file" => false,
            _ => return None,
        };
        entries.insert(
            tail,
            FolderMoveEntry {
                content_hash: saved.content_hash.clone(),
                is_directory,
                directory_identity: if is_directory {
                    Some(saved.directory_identity.clone()?)
                } else {
                    None
                },
            },
        );
    }
    entries
        .contains_key(Path::new(""))
        .then_some(FolderMovePrecondition {
            identity,
            entries,
            remote_witness: None,
        })
}

pub fn folder_subtree_matches_precondition(
    precondition: &FolderMovePrecondition,
    root: &Path,
    local_entries: &[LocalEntry],
) -> bool {
    let actual = local_entries
        .iter()
        .filter(|entry| entry.relative_path.starts_with(root))
        .map(|entry| {
            (
                entry
                    .relative_path
                    .strip_prefix(root)
                    .expect("starts_with checked")
                    .to_path_buf(),
                FolderMoveEntry {
                    content_hash: entry.content_hash.clone(),
                    is_directory: entry.is_directory,
                    directory_identity: entry.directory_identity.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    actual == precondition.entries
}

fn folder_remote_witness(
    root_id: &str,
    selected_remote_root: Option<&str>,
    remote_by_id: &BTreeMap<&str, &RemoteEntry>,
    all_live_remote_by_id: &BTreeMap<&str, &RemoteEntry>,
    remote_paths: &BTreeMap<String, PathBuf>,
) -> Option<FolderRemoteWitness> {
    let root_path = remote_paths.get(root_id)?.clone();
    let root = remote_by_id.get(root_id)?;
    if root.kind != RemoteEntryKind::Folder {
        return None;
    }
    let entries = remote_by_id
        .iter()
        .filter_map(|(id, entry)| {
            remote_paths
                .get(*id)
                .filter(|path| path.starts_with(&root_path))
                .map(|path| {
                    (
                        (*id).to_string(),
                        FolderRemoteWitnessEntry {
                            parent_id: entry.parent_id.clone(),
                            relative_path: path.clone(),
                            kind: entry.kind.clone(),
                            revision: entry.revision,
                            content_hash: entry.content_hash.clone(),
                        },
                    )
                })
        })
        .collect::<BTreeMap<_, _>>();
    let selected_root_ancestry = match selected_remote_root {
        Some(selected_root) => Some(selected_remote_root_ancestry(
            selected_root,
            all_live_remote_by_id,
        )?),
        None => None,
    };
    entries
        .contains_key(root_id)
        .then_some(FolderRemoteWitness {
            selected_root_ancestry,
            root_id: root_id.to_string(),
            root_path,
            entries,
        })
}

fn selected_remote_root_ancestry(
    selected_root: &str,
    remote_by_id: &BTreeMap<&str, &RemoteEntry>,
) -> Option<Vec<FolderRemoteWitnessNode>> {
    let mut ancestry = Vec::new();
    let mut seen = BTreeSet::new();
    let mut current = Some(selected_root);
    while let Some(id) = current {
        if !seen.insert(id) {
            return None;
        }
        let entry = remote_by_id.get(id)?;
        // A selected local sync root and every ancestor that defines its
        // effective Drive location must remain directories.
        if entry.kind != RemoteEntryKind::Folder {
            return None;
        }
        ancestry.push(FolderRemoteWitnessNode {
            id: entry.id.clone(),
            parent_id: entry.parent_id.clone(),
            name: entry.name.clone(),
            kind: entry.kind.clone(),
            revision: entry.revision,
            content_hash: entry.content_hash.clone(),
        });
        current = entry.parent_id.as_deref();
    }
    Some(ancestry)
}

/// Capture the exact remote subtree and selected-root ancestry from one scoped
/// manifest. Executors use this at their terminal preflight when the planner's
/// outbound folder precondition deliberately contains only local evidence.
pub fn capture_folder_remote_witness(
    root_id: &str,
    selected_remote_root: Option<&str>,
    remote_entries: &[RemoteEntry],
) -> Option<FolderRemoteWitness> {
    let Ok(paths) = map_remote_paths(remote_entries, selected_remote_root) else {
        return None;
    };
    let remote_by_id = remote_entries
        .iter()
        .filter(|entry| !entry.trashed && paths.contains_key(&entry.id))
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let all_live_remote_by_id = remote_entries
        .iter()
        .filter(|entry| !entry.trashed)
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    folder_remote_witness(
        root_id,
        selected_remote_root,
        &remote_by_id,
        &all_live_remote_by_id,
        &paths,
    )
}

/// Rebuild a remote subtree witness from a just-fetched manifest. Any changed
/// selected root, topology, metadata, body revision/hash, added descendant, or
/// removed descendant invalidates an inbound native folder move.
pub fn folder_remote_witness_matches(
    precondition: &FolderMovePrecondition,
    selected_remote_root: Option<&str>,
    remote_entries: &[RemoteEntry],
) -> bool {
    let Some(expected) = precondition.remote_witness.as_ref() else {
        return false;
    };
    capture_folder_remote_witness(&expected.root_id, selected_remote_root, remote_entries)
        == Some(expected.clone())
}

fn local_directory_identity_roots(
    local_entries: &[LocalEntry],
    identity: &crate::DirectoryIdentity,
) -> Vec<PathBuf> {
    let mut roots = local_entries
        .iter()
        .filter(|entry| entry.is_directory && entry.directory_identity.as_ref() == Some(identity))
        .map(|entry| entry.relative_path.clone())
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    roots
}

fn possible_folder_relocation_roots(
    folder_id: &str,
    old_root: &Path,
    baseline: &BTreeMap<String, BaselineEntry>,
    remote_by_id: &BTreeMap<&str, &RemoteEntry>,
    local_entries: &[LocalEntry],
) -> Vec<PathBuf> {
    let mut roots = local_entries
        .iter()
        .filter(|entry| entry.is_directory && entry.relative_path != old_root)
        .filter(|entry| {
            !baseline.iter().any(|(id, saved)| {
                id.as_str() != folder_id
                    && saved.kind.eq_ignore_ascii_case("folder")
                    && saved.relative_path == entry.relative_path
                    && remote_by_id.contains_key(id.as_str())
            })
        })
        .map(|entry| entry.relative_path.clone())
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    roots
}

fn remote_folder_subtree_shape_matches(
    baseline: &BTreeMap<String, BaselineEntry>,
    remote_by_id: &BTreeMap<&str, &RemoteEntry>,
    live_remote_paths: &BTreeMap<String, PathBuf>,
    old_root: &Path,
    live_root: &Path,
) -> bool {
    let expected_ids = baseline
        .iter()
        .filter(|(_, entry)| entry.relative_path.starts_with(old_root))
        .map(|(id, _)| id.as_str())
        .collect::<BTreeSet<_>>();
    let actual_ids = remote_by_id
        .keys()
        .filter_map(|id| {
            live_remote_paths
                .get(*id)
                .is_some_and(|path| path.starts_with(live_root))
                .then_some(*id)
        })
        .collect::<BTreeSet<_>>();
    expected_ids == actual_ids
        && expected_ids.into_iter().all(|id| {
            let Some(saved) = baseline.get(id) else {
                return false;
            };
            let Some(remote) = remote_by_id.get(id) else {
                return false;
            };
            let Some(path) = live_remote_paths.get(id) else {
                return false;
            };
            let Ok(tail) = saved.relative_path.strip_prefix(old_root) else {
                return false;
            };
            path == &live_root.join(tail)
                && matches!(
                    (&remote.kind, saved.kind.as_str()),
                    (RemoteEntryKind::Folder, "folder") | (RemoteEntryKind::File, "file")
                )
        })
}

fn outbound_folder_destination_is_safe(
    live_remote_paths: &BTreeMap<String, PathBuf>,
    remote_by_id: &BTreeMap<&str, &RemoteEntry>,
    moving_id: &str,
    destination: &Path,
) -> bool {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent_is_remote_folder = match parent {
        None => true,
        Some(parent) => remote_by_id.iter().any(|(id, entry)| {
            entry.kind == RemoteEntryKind::Folder
                && live_remote_paths
                    .get(*id)
                    .is_some_and(|path| path == parent)
        }),
    };
    parent_is_remote_folder
        && !live_remote_paths.iter().any(|(id, path)| {
            id != moving_id && (path == destination || path.starts_with(destination))
        })
}

fn accept_folder_move_paths(
    baseline: &BTreeMap<String, BaselineEntry>,
    live_remote_paths: &BTreeMap<String, PathBuf>,
    old_root: &Path,
    destination: &Path,
    outbound: bool,
    result: &mut FolderMovePlanning,
) {
    for (id, saved) in baseline
        .iter()
        .filter(|(_, entry)| entry.relative_path.starts_with(old_root))
    {
        let tail = saved
            .relative_path
            .strip_prefix(old_root)
            .expect("starts_with checked");
        result
            .effective_baseline_paths
            .insert(id.clone(), destination.join(tail));
    }
    if outbound {
        for (id, path) in live_remote_paths
            .iter()
            .filter(|(_, path)| path.starts_with(old_root))
        {
            let tail = path.strip_prefix(old_root).expect("starts_with checked");
            result
                .effective_remote_paths
                .insert(id.clone(), destination.join(tail));
        }
    }
}

fn claim_local_subtree(
    root: &Path,
    local_entries: &[LocalEntry],
    claimed_local_paths: &mut HashSet<PathBuf>,
) {
    for entry in local_entries
        .iter()
        .filter(|entry| entry.relative_path.starts_with(root))
    {
        claimed_local_paths.insert(entry.relative_path.clone());
    }
}

#[allow(clippy::too_many_arguments)]
fn reserve_folder_identity_review(
    baseline: &BTreeMap<String, BaselineEntry>,
    live_remote_paths: &BTreeMap<String, PathBuf>,
    local_entries: &[LocalEntry],
    old_root: &Path,
    live_root: Option<&PathBuf>,
    relocation_roots: &[PathBuf],
    result: &mut FolderMovePlanning,
    plan: &mut ReconcilePlan,
    reason: &str,
) {
    for (id, saved) in baseline
        .iter()
        .filter(|(_, entry)| entry.relative_path.starts_with(old_root))
    {
        result.contained_baseline_ids.insert(id.clone());
        result.contained_remote_ids.insert(id.clone());
        result
            .claimed_local_paths
            .insert(saved.relative_path.clone());
    }
    if let Some(live_root) = live_root {
        for (id, _) in live_remote_paths
            .iter()
            .filter(|(_, path)| path.starts_with(live_root))
        {
            result.contained_remote_ids.insert(id.clone());
        }
    }
    let mut roots = BTreeSet::from([old_root.to_path_buf()]);
    if let Some(live_root) = live_root {
        roots.insert(live_root.clone());
    }
    roots.extend(relocation_roots.iter().cloned());
    for root in roots {
        claim_local_subtree(&root, local_entries, &mut result.claimed_local_paths);
    }
    let mut item = review(
        ReviewKind::PathConflict,
        old_root,
        &format!(
            "{reason} This check made no additional move, upload, download, or overwrite in this folder; inspect it and recheck."
        ),
        vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    );
    item.is_directory = true;
    item.descendant_count = baseline
        .values()
        .filter(|entry| entry.relative_path.starts_with(old_root))
        .count()
        .saturating_sub(1);
    plan.reviews.push(item);
}

fn effective_local_entries<'a>(
    local_entries: &'a [LocalEntry],
    pending_inbound_transforms: &[(PathBuf, PathBuf)],
) -> HashMap<PathBuf, &'a LocalEntry> {
    let mut entries = local_entries
        .iter()
        .map(|entry| (entry.relative_path.clone(), entry))
        .collect::<HashMap<_, _>>();
    for (old_root, destination) in pending_inbound_transforms {
        let moved = local_entries
            .iter()
            .filter(|entry| entry.relative_path.starts_with(old_root))
            .map(|entry| {
                let tail = entry
                    .relative_path
                    .strip_prefix(old_root)
                    .expect("starts_with checked");
                (entry.relative_path.clone(), destination.join(tail), entry)
            })
            .collect::<Vec<_>>();
        for (old_path, _, _) in &moved {
            entries.remove(old_path);
        }
        for (_, new_path, entry) in moved {
            entries.insert(new_path, entry);
        }
    }
    entries
}

fn unique_file_rename_candidates<'a>(
    common: &BaselineEntry,
    local_entries: &'a [LocalEntry],
    claimed: &HashSet<PathBuf>,
    baseline: &BTreeMap<String, BaselineEntry>,
    live_remote: &BTreeMap<&str, &RemoteEntry>,
) -> Vec<&'a LocalEntry> {
    // Folder rows all share `None` content hashes; a folder move requires a
    // subtree identity protocol, not a single row match. Leave it reviewed.
    if !common.kind.eq_ignore_ascii_case("file") {
        return Vec::new();
    }
    let mut matches = local_entries
        .iter()
        .filter(|candidate| {
            !claimed.contains(&candidate.relative_path)
                && same_baseline_and_local(common, candidate)
                && !baseline.iter().any(|(id, other)| {
                    id != &common.remote_id
                        && other.relative_path == candidate.relative_path
                        && live_remote.contains_key(id.as_str())
                })
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    matches
}

fn same_baseline_and_local(common: &BaselineEntry, local: &LocalEntry) -> bool {
    let baseline_is_directory = common.kind.eq_ignore_ascii_case("folder");
    if local.is_directory != baseline_is_directory {
        return false;
    }
    if baseline_is_directory {
        // Legacy v1 rows deliberately allow an unchanged observation at the
        // same path so the next successful baseline can capture an identity.
        // They never enter `plan_identity_folder_moves` for an automatic move.
        common.directory_identity.is_none() || local.directory_identity == common.directory_identity
    } else {
        local.content_hash == common.content_hash
    }
}

fn descendants(path: &Path, entries: &[LocalEntry]) -> usize {
    entries
        .iter()
        .filter(|entry| entry.relative_path.starts_with(path))
        .count()
        .saturating_sub(1)
}

fn baseline_descendants(path: &Path, baseline: &BTreeMap<String, BaselineEntry>) -> usize {
    baseline
        .values()
        .filter(|entry| entry.relative_path.starts_with(path))
        .count()
        .saturating_sub(1)
}

fn review(kind: ReviewKind, path: &Path, summary: &str, actions: Vec<ReviewAction>) -> ReviewItem {
    ReviewItem {
        id: format!("{:?}:{}", kind, path.display()),
        kind,
        relative_path: path.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary: summary.to_string(),
        actions,
    }
}

fn local_deletion_review(path: &Path, descendant_count: usize, is_directory: bool) -> ReviewItem {
    let actions = if is_directory {
        vec![ReviewAction::RestoreLocalCopy]
    } else {
        vec![
            ReviewAction::DeleteFromDrive,
            ReviewAction::RestoreLocalCopy,
        ]
    };
    let mut item = review(
        ReviewKind::LocalDeletion,
        path,
        if is_directory {
            "Deleted locally. Folder trash stays disabled until Drive supports conditional recursive deletion; restore the local copy to keep this mirror safe."
        } else {
            "Deleted locally. Choose whether to move the Drive file to trash or restore the local copy."
        },
        actions,
    );
    item.descendant_count = descendant_count;
    item.is_directory = is_directory;
    item
}

fn remote_deletion_review(path: &Path, descendant_count: usize) -> ReviewItem {
    let mut item = review(
        ReviewKind::RemoteDeletion,
        path,
        "Deleted in Drive. Choose whether to remove the local copy or restore it to Drive.",
        vec![ReviewAction::RemoveLocalCopy, ReviewAction::RestoreToDrive],
    );
    item.descendant_count = descendant_count;
    item
}

fn delete_edit_review(summary: &str, path: &Path) -> ReviewItem {
    review(
        ReviewKind::DeleteEditConflict,
        path,
        summary,
        vec![
            ReviewAction::OpenConflictCopies,
            ReviewAction::RestoreToDrive,
        ],
    )
}

fn content_conflict_review(local_path: &Path, conflict_path: &Path) -> ReviewItem {
    let mut item = review(
        ReviewKind::ContentConflict,
        conflict_path,
        "Both copies changed. The Drive copy is written beside the local copy.",
        vec![ReviewAction::OpenConflictCopies],
    );
    // Bind the stable review identity to the tracked file, not the
    // timestamped keep-both copy. A planning-only recheck can then retain the
    // original conflict-copy path instead of pointing the UI at a new file
    // that was never written.
    item.id = content_conflict_review_id(local_path);
    item
}

fn path_conflict_review(path: &Path) -> ReviewItem {
    review(
        ReviewKind::PathConflict,
        path,
        "Local and Drive paths changed concurrently. Neither location is overwritten.",
        vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    )
}

fn new_remote_collision_review(path: &Path) -> ReviewItem {
    review(
        ReviewKind::PathConflict,
        path,
        "Drive has a new item at this local path. The existing local bytes are preserved until you choose a location.",
        vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    )
}

fn remote_path_compatibility_review(issue: &RemotePathIssue) -> ReviewItem {
    ReviewItem {
        id: format!("remote-path:{}:{}", issue.remote_id, issue.path.display()),
        kind: ReviewKind::UnsafePath,
        relative_path: issue.path.clone(),
        descendant_count: 0,
        is_directory: false,
        summary: format!(
            "Drive path cannot be mirrored on Windows because {}. No local files were changed; rename or remove the incompatible Drive item, then recheck.",
            issue.reason
        ),
        actions: Vec::new(),
    }
}

/// True only for the persistent path compatibility reviews created from
/// remote manifests or local filesystem inspection.
/// The desktop shell uses this distinction to clear a path-only review after a
/// planning-only recheck sees a compatible manifest, without treating a
/// deletion or conflict review as resolved.
pub fn is_path_compatibility_review(item: &ReviewItem) -> bool {
    item.kind == ReviewKind::UnsafePath
        && (item.id.starts_with("remote-path:") || item.id.starts_with("local-path:"))
}
#[cfg(test)]
#[path = "mirror_tests.rs"]
mod tests;

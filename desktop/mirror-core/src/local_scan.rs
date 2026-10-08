use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use walkdir::WalkDir;

use crate::{
    hash_reader_bounded_with_cancellation,
    mirror::{LocalEntry, LocalPathIssue, LocalTreeInspection},
    paths::windows_paths_compare_ignore_case,
    validate_windows_compatible_relative, DesktopError, ReadBudget, Result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalScanLimits {
    pub max_entries: usize,
    pub max_file_bytes: u64,
    pub max_total_file_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalTreeUsage {
    pub logical_bytes: u64,
    pub file_count: usize,
    pub folder_count: usize,
}

impl Default for LocalScanLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_file_bytes: 2 * 1024 * 1024 * 1024,
            max_total_file_bytes: 20 * 1024 * 1024 * 1024,
        }
    }
}

/// Inspect one local tree under an aggregate entry/byte budget. Every file is
/// size-checked on its opened handle before hashing and the reader itself is
/// bounded, so a growing file cannot turn one scan into unbounded work.
pub fn inspect_local_tree(root: &Path) -> Result<LocalTreeInspection> {
    inspect_local_tree_with_limits(root, LocalScanLimits::default())
}

pub fn inspect_local_tree_with_cancellation(
    root: &Path,
    mut check: impl FnMut() -> Result<()>,
) -> Result<LocalTreeInspection> {
    let limits = LocalScanLimits::default();
    let mut read_budget = ReadBudget::new(limits.max_total_file_bytes);
    inspect_local_tree_with_limits_and_budget(root, limits, &mut read_budget, &mut check)
}

pub fn inspect_local_tree_with_budget(
    root: &Path,
    read_budget: &mut ReadBudget,
) -> Result<LocalTreeInspection> {
    inspect_local_tree_with_limits_and_budget(
        root,
        LocalScanLimits::default(),
        read_budget,
        &mut || Ok(()),
    )
}

pub fn inspect_local_tree_with_budget_and_cancellation(
    root: &Path,
    read_budget: &mut ReadBudget,
    mut check: impl FnMut() -> Result<()>,
) -> Result<LocalTreeInspection> {
    inspect_local_tree_with_limits_and_budget(
        root,
        LocalScanLimits::default(),
        read_budget,
        &mut check,
    )
}

/// Measure the logical file size of one configured sync root without reading
/// file bodies. The same entry, link, path, and aggregate bounds as a sync scan
/// apply, so a status projection cannot turn into an unbounded filesystem walk
/// or follow content outside the selected root.
pub fn measure_local_tree_usage(root: &Path) -> Result<LocalTreeUsage> {
    measure_local_tree_usage_with_limits(root, LocalScanLimits::default())
}

/// The bounded logical-usage measurement with caller-supplied aggregate
/// limits. Callers that combine several configured roots use the remaining
/// aggregate byte budget for each root and fail closed rather than reporting a
/// partial total.
pub fn measure_local_tree_usage_with_limits(
    root: &Path,
    limits: LocalScanLimits,
) -> Result<LocalTreeUsage> {
    crate::paths::ensure_not_link(root)?;
    let mut usage = LocalTreeUsage {
        logical_bytes: 0,
        file_count: 0,
        folder_count: 0,
    };
    let mut visited = 0usize;
    let walker = WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .into_iter();
    for entry in walker {
        let entry = entry.map_err(|error| DesktopError::UnsafePath(error.to_string()))?;
        visited = visited.checked_add(1).ok_or_else(|| {
            DesktopError::InvalidState("local usage entry count overflowed".to_string())
        })?;
        if visited > limits.max_entries {
            return Err(DesktopError::InvalidState(format!(
                "local tree exceeds the {}-entry usage limit",
                limits.max_entries
            )));
        }
        crate::paths::ensure_not_link(entry.path())?;
        let relative_path = relative_path(root, entry.path())?;
        if relative_path == Path::new(crate::paths::PAIR_MARKER_FILE) {
            continue;
        }
        validate_windows_compatible_relative(&relative_path)
            .map_err(|issue| DesktopError::UnsafePath(issue.reason))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            usage.folder_count = usage.folder_count.checked_add(1).ok_or_else(|| {
                DesktopError::InvalidState("local folder count overflowed".to_string())
            })?;
        } else if metadata.is_file() {
            let file = crate::paths::open_local_regular_file(entry.path())?;
            crate::paths::ensure_single_linked_regular_file(&file, entry.path())?;
            let opened = file.metadata()?;
            if !opened.is_file() || opened.len() > limits.max_file_bytes {
                return Err(DesktopError::InvalidState(format!(
                    "local file exceeds the {}-byte usage limit: {}",
                    limits.max_file_bytes,
                    relative_path.display()
                )));
            }
            usage.logical_bytes =
                usage
                    .logical_bytes
                    .checked_add(opened.len())
                    .ok_or_else(|| {
                        DesktopError::InvalidState("local usage byte count overflowed".to_string())
                    })?;
            if usage.logical_bytes > limits.max_total_file_bytes {
                return Err(DesktopError::InvalidState(format!(
                    "local tree exceeds the {}-byte aggregate usage limit",
                    limits.max_total_file_bytes
                )));
            }
            usage.file_count = usage.file_count.checked_add(1).ok_or_else(|| {
                DesktopError::InvalidState("local file count overflowed".to_string())
            })?;
        } else {
            return Err(DesktopError::UnsafePath(format!(
                "unsupported filesystem entry: {}",
                entry.path().display()
            )));
        }
    }
    Ok(usage)
}

pub(crate) fn inspect_local_tree_with_limits(
    root: &Path,
    limits: LocalScanLimits,
) -> Result<LocalTreeInspection> {
    let mut read_budget = ReadBudget::new(limits.max_total_file_bytes);
    inspect_local_tree_with_limits_and_budget(root, limits, &mut read_budget, &mut || Ok(()))
}

fn inspect_local_tree_with_limits_and_budget(
    root: &Path,
    limits: LocalScanLimits,
    read_budget: &mut ReadBudget,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<LocalTreeInspection> {
    crate::paths::ensure_not_link(root)?;
    let mut inspection = LocalTreeInspection::default();
    let mut visited = 0usize;
    let mut total_file_bytes = 0u64;
    let mut walker = WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .into_iter();
    while let Some(entry) = walker.next() {
        check()?;
        let entry = entry.map_err(|error| DesktopError::UnsafePath(error.to_string()))?;
        visited = visited.checked_add(1).ok_or_else(|| {
            DesktopError::InvalidState("local scan entry count overflowed".to_string())
        })?;
        if visited > limits.max_entries {
            return Err(DesktopError::InvalidState(format!(
                "local tree exceeds the {}-entry scan limit",
                limits.max_entries
            )));
        }
        if let Err(error) = crate::paths::ensure_not_link(entry.path()) {
            if matches!(error, DesktopError::UnsafeLink(_)) {
                let relative_path = relative_path(root, entry.path())?;
                inspection.issues.push(LocalPathIssue {
                    path: relative_path,
                    reason: "it is a symbolic link or Windows reparse point".to_string(),
                });
                if entry.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                continue;
            }
            return Err(error);
        }
        let relative_path = relative_path(root, entry.path())?;
        if relative_path == Path::new(crate::paths::PAIR_MARKER_FILE) {
            continue;
        }
        if let Err(issue) = validate_windows_compatible_relative(&relative_path) {
            inspection.issues.push(LocalPathIssue {
                path: relative_path,
                reason: issue.reason,
            });
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            inspection.entries.push(LocalEntry {
                relative_path,
                content_hash: None,
                size_bytes: 0,
                is_directory: true,
                directory_identity: None,
            });
        } else if metadata.is_file() {
            let mut file = crate::paths::open_local_regular_file(entry.path())?;
            if let Err(error) = crate::paths::ensure_single_linked_regular_file(&file, entry.path())
            {
                if matches!(error, DesktopError::UnsafeLink(_)) {
                    inspection.issues.push(LocalPathIssue {
                        path: relative_path,
                        reason: "it has more than one filesystem hard link".to_string(),
                    });
                    continue;
                }
                return Err(error);
            }
            let opened = file.metadata()?;
            if !opened.is_file() || opened.len() > limits.max_file_bytes {
                return Err(DesktopError::InvalidState(format!(
                    "local file exceeds the {}-byte scan limit: {}",
                    limits.max_file_bytes,
                    relative_path.display()
                )));
            }
            let remaining_scan_bytes = limits
                .max_total_file_bytes
                .checked_sub(total_file_bytes)
                .ok_or_else(|| {
                    DesktopError::InvalidState(format!(
                        "local tree exceeds the {}-byte aggregate scan limit",
                        limits.max_total_file_bytes
                    ))
                })?;
            if opened.len() > remaining_scan_bytes {
                return Err(DesktopError::InvalidState(format!(
                    "local tree exceeds the {}-byte aggregate scan limit",
                    limits.max_total_file_bytes
                )));
            }
            // Reserve the opened length from the pass-wide budget before any
            // hashing. A file that grows after admission is rejected after at
            // most one boundary byte instead of consuming another scan's
            // allowance.
            read_budget.charge(opened.len())?;
            let (content_hash, actual_bytes) =
                hash_reader_bounded_with_cancellation(&mut file, opened.len(), &mut *check)?;
            validate_hashed_file_length(opened.len(), actual_bytes, &relative_path)?;
            total_file_bytes =
                charge_scan_bytes(total_file_bytes, actual_bytes, limits.max_total_file_bytes)?;
            inspection.entries.push(LocalEntry {
                relative_path,
                content_hash: Some(content_hash),
                size_bytes: actual_bytes,
                is_directory: false,
                directory_identity: None,
            });
        } else {
            return Err(DesktopError::UnsafePath(format!(
                "unsupported filesystem entry: {}",
                entry.path().display()
            )));
        }
    }
    remove_case_collisions(&mut inspection);
    inspection
        .entries
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    inspection
        .issues
        .sort_by(|left, right| (&left.path, &left.reason).cmp(&(&right.path, &right.reason)));
    Ok(inspection)
}

fn relative_path(root: &Path, path: &Path) -> Result<PathBuf> {
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|error| DesktopError::UnsafePath(error.to_string()))
}

fn remove_case_collisions(inspection: &mut LocalTreeInspection) {
    let mut order = (0..inspection.entries.len()).collect::<Vec<_>>();
    order.sort_by(|left, right| {
        windows_paths_compare_ignore_case(
            &inspection.entries[*left].relative_path,
            &inspection.entries[*right].relative_path,
        )
    });
    let mut colliding = HashSet::new();
    for pair in order.windows(2) {
        if windows_paths_compare_ignore_case(
            &inspection.entries[pair[0]].relative_path,
            &inspection.entries[pair[1]].relative_path,
        )
        .is_eq()
        {
            colliding.insert(pair[0]);
            colliding.insert(pair[1]);
        }
    }
    let colliding_paths = colliding
        .into_iter()
        .map(|index| inspection.entries[index].relative_path.clone())
        .collect::<HashSet<_>>();
    inspection
        .entries
        .retain(|entry| !colliding_paths.contains(&entry.relative_path));
    inspection
        .issues
        .extend(colliding_paths.into_iter().map(|path| {
            LocalPathIssue {
            path,
            reason:
                "Windows treats this local path as the same path when matching case-insensitively"
                    .to_string(),
        }
        }));
}

fn validate_hashed_file_length(expected: u64, actual: u64, relative_path: &Path) -> Result<()> {
    if expected != actual {
        return Err(DesktopError::InvalidState(format!(
            "local file changed while it was being hashed: {}",
            relative_path.display()
        )));
    }
    Ok(())
}

fn charge_scan_bytes(current: u64, actual: u64, maximum: u64) -> Result<u64> {
    let total = current.checked_add(actual).ok_or_else(|| {
        DesktopError::InvalidState("local scan byte count overflowed".to_string())
    })?;
    if total > maximum {
        return Err(DesktopError::InvalidState(format!(
            "local tree exceeds the {maximum}-byte aggregate scan limit"
        )));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_reader_bounded;

    #[test]
    fn usage_counts_logical_file_bytes_without_counting_the_pair_marker() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("Folder")).unwrap();
        fs::write(root.path().join("Folder").join("one.bin"), b"1234").unwrap();
        fs::write(root.path().join("two.bin"), b"12").unwrap();
        fs::write(root.path().join(crate::paths::PAIR_MARKER_FILE), b"marker").unwrap();

        assert_eq!(
            measure_local_tree_usage(root.path()).unwrap(),
            LocalTreeUsage {
                logical_bytes: 6,
                file_count: 2,
                folder_count: 1,
            }
        );
    }
    use crate::bounded_io::BUFFER_BYTES;
    use std::io::Read;
    use tempfile::tempdir;

    #[test]
    fn aggregate_bytes_are_rejected_using_the_hashed_file_size() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("one.bin"), b"123").unwrap();
        fs::write(root.path().join("two.bin"), b"456").unwrap();
        let limits = LocalScanLimits {
            max_entries: 10,
            max_file_bytes: 4,
            max_total_file_bytes: 5,
        };
        assert!(inspect_local_tree_with_limits(root.path(), limits).is_err());
    }

    #[test]
    fn repeated_tree_scans_share_one_read_budget() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("payload.bin"), b"123").unwrap();
        let mut budget = ReadBudget::new(5);
        inspect_local_tree_with_budget(root.path(), &mut budget).unwrap();
        assert!(inspect_local_tree_with_budget(root.path(), &mut budget).is_err());
    }

    #[test]
    fn multiply_linked_regular_file_becomes_a_non_uploadable_issue() {
        let directory = tempdir().unwrap();
        let root = directory.path().join("pair");
        fs::create_dir(&root).unwrap();
        let outside = directory.path().join("outside.txt");
        fs::write(&outside, b"outside bytes").unwrap();
        fs::hard_link(&outside, root.join("inside.txt")).unwrap();

        let inspection = inspect_local_tree(&root).unwrap();
        assert!(inspection.entries.is_empty());
        assert_eq!(inspection.issues.len(), 1);
        assert_eq!(inspection.issues[0].path, PathBuf::from("inside.txt"));
        assert!(inspection.issues[0].reason.contains("hard link"));
    }

    #[test]
    fn hashing_uses_a_fixed_size_streaming_buffer() {
        struct LargeReader {
            remaining: usize,
            maximum_requested: usize,
        }
        impl Read for LargeReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.maximum_requested = self.maximum_requested.max(buffer.len());
                let count = self.remaining.min(buffer.len());
                buffer[..count].fill(b'x');
                self.remaining -= count;
                Ok(count)
            }
        }
        let total = BUFFER_BYTES * 3 + 7;
        let mut reader = LargeReader {
            remaining: total,
            maximum_requested: 0,
        };
        let (_, hashed_bytes) = hash_reader_bounded(&mut reader, total as u64).unwrap();
        assert_eq!(hashed_bytes, total as u64);
        assert_eq!(reader.maximum_requested, BUFFER_BYTES);

        let mut reader = LargeReader {
            remaining: 3,
            maximum_requested: 0,
        };
        assert!(hash_reader_bounded(&mut reader, 1).is_err());
        assert_eq!(reader.maximum_requested, 2);
    }

    #[test]
    fn changed_file_after_admission_is_rejected_and_not_counted() {
        let path = Path::new("mutated.bin");
        assert!(validate_hashed_file_length(3, 4, path).is_err());
        assert_eq!(charge_scan_bytes(5, 5, 10).unwrap(), 10);
        assert!(charge_scan_bytes(5, 6, 10).is_err());
    }
}

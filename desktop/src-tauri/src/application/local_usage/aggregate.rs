//! Aggregate, fail-closed usage projection for all configured Drive roots.

use std::{collections::HashSet, path::Path};

use shellx_drive_desktop_core::LocalTreeUsage;

use super::LocalUsageCache;

const MAX_AGGREGATE_USAGE_BYTES: u64 = 20 * 1024 * 1024 * 1024;

pub(super) fn measure_all<'a>(
    cache: &LocalUsageCache,
    roots: impl IntoIterator<Item = &'a Path>,
) -> Option<LocalTreeUsage> {
    measure_all_with_limit(cache, roots, MAX_AGGREGATE_USAGE_BYTES)
}

fn measure_all_with_limit<'a>(
    cache: &LocalUsageCache,
    roots: impl IntoIterator<Item = &'a Path>,
    max_total_file_bytes: u64,
) -> Option<LocalTreeUsage> {
    let mut seen = HashSet::new();
    let mut total = empty_usage();
    for root in roots.into_iter().filter(|root| seen.insert(path_key(root))) {
        let remaining = max_total_file_bytes.checked_sub(total.logical_bytes)?;
        let usage = cache.measure_with_total_limit(root, remaining)?;
        total = checked_sum(total, usage)?;
        if total.logical_bytes > max_total_file_bytes {
            return None;
        }
    }
    Some(total)
}

fn path_key(root: &Path) -> String {
    root.components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("\0")
}

fn empty_usage() -> LocalTreeUsage {
    LocalTreeUsage {
        logical_bytes: 0,
        file_count: 0,
        folder_count: 0,
    }
}

fn checked_sum(left: LocalTreeUsage, right: LocalTreeUsage) -> Option<LocalTreeUsage> {
    Some(LocalTreeUsage {
        logical_bytes: left.logical_bytes.checked_add(right.logical_bytes)?,
        file_count: left.file_count.checked_add(right.file_count)?,
        folder_count: left.folder_count.checked_add(right.folder_count)?,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn aggregate_usage_sums_all_unique_roots_once() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        fs::write(first.join("one.bin"), b"123").unwrap();
        fs::write(second.join("two.bin"), b"1234").unwrap();

        assert_eq!(
            measure_all_with_limit(
                &LocalUsageCache::default(),
                [first.as_path(), second.as_path(), first.as_path()],
                10,
            ),
            Some(LocalTreeUsage {
                logical_bytes: 7,
                file_count: 2,
                folder_count: 0,
            })
        );
    }

    #[test]
    fn aggregate_usage_is_unavailable_instead_of_partial_when_the_bound_is_hit() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        fs::write(first.join("one.bin"), b"123").unwrap();
        fs::write(second.join("two.bin"), b"1234").unwrap();

        assert_eq!(
            measure_all_with_limit(
                &LocalUsageCache::default(),
                [first.as_path(), second.as_path()],
                6
            ),
            None
        );
    }

    #[test]
    fn aggregate_usage_is_unavailable_when_any_configured_root_is_unsafe() {
        let directory = tempfile::tempdir().unwrap();
        let measured = directory.path().join("measured");
        fs::create_dir(&measured).unwrap();
        fs::write(measured.join("one.bin"), b"123").unwrap();
        let missing = directory.path().join("missing");

        assert_eq!(
            measure_all_with_limit(
                &LocalUsageCache::default(),
                [measured.as_path(), missing.as_path()],
                10,
            ),
            None
        );
    }
}

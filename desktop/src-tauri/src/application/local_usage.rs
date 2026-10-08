//! Cached, bounded local sync-root usage projection for the desktop UI.

mod aggregate;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use shellx_drive_desktop_core::{
    measure_local_tree_usage_with_limits, LocalScanLimits, LocalTreeUsage,
};

const CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
struct CachedUsage {
    measured_at: Instant,
    usage: Option<LocalTreeUsage>,
}

#[derive(Default)]
pub(crate) struct LocalUsageCache {
    entries: Mutex<HashMap<PathBuf, CachedUsage>>,
}

impl LocalUsageCache {
    pub(crate) fn measure_all<'a>(
        &self,
        roots: impl IntoIterator<Item = &'a Path>,
    ) -> Option<LocalTreeUsage> {
        aggregate::measure_all(self, roots)
    }

    fn measure_with_total_limit(
        &self,
        root: &Path,
        max_total_file_bytes: u64,
    ) -> Option<LocalTreeUsage> {
        let now = Instant::now();
        if let Some(cached) = self
            .entries
            .lock()
            .expect("local usage cache lock")
            .get(root)
            .copied()
            .filter(|cached| now.duration_since(cached.measured_at) < CACHE_TTL)
        {
            return cached
                .usage
                .filter(|usage| usage.logical_bytes <= max_total_file_bytes);
        }
        let usage = measure_local_tree_usage_with_limits(
            root,
            LocalScanLimits {
                max_total_file_bytes,
                ..LocalScanLimits::default()
            },
        )
        .ok();
        self.entries.lock().expect("local usage cache lock").insert(
            root.to_path_buf(),
            CachedUsage {
                measured_at: now,
                usage,
            },
        );
        usage
    }

    pub(crate) fn invalidate(&self) {
        self.entries.lock().expect("local usage cache lock").clear();
    }
}

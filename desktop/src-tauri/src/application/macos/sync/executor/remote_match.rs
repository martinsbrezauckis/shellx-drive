//! Pure terminal remote-file witness comparison.

use std::path::Path;

use shellx_drive_desktop_core::{map_remote_paths, RemoteEntry};

pub(super) fn exact_file(
    entries: &[RemoteEntry],
    selected_root: Option<&str>,
    expected: &RemoteEntry,
    expected_path: &Path,
) -> bool {
    let Ok(paths) = map_remote_paths(entries, selected_root) else {
        return false;
    };
    entries.iter().any(|current| {
        current.id == expected.id
            && !current.trashed
            && current.kind == expected.kind
            && current.revision == expected.revision
            && current.content_hash == expected.content_hash
            && current.size_bytes == expected.size_bytes
            && paths
                .get(&current.id)
                .is_some_and(|path| path == expected_path)
    })
}

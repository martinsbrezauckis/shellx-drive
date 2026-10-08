//! Count retained conflict bodies through the already admitted cache root.

use std::{io, path::Path};

use cap_fs_ext::DirExt;

use super::{SafeCacheInput, SafeCacheRoot};

const MAX_CACHED_WORKSPACES: usize = 1024;
const MAX_FILES_PER_WORKSPACE: usize = 10_000;
const MAX_SCANNED_FILES: usize = 100_000;
const MAX_FILENAME_BYTES: usize = 8 * 1024 * 1024;
const RECOVERY_SUFFIX: &[u8] = b".remote-conflict";

impl SafeCacheRoot {
    pub(crate) fn retained_recovery_bytes(&self) -> io::Result<u64> {
        let workspaces = match self.dir.open_dir_nofollow("workspaces") {
            Ok(workspaces) => workspaces,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error),
        };
        let mut workspace_count = 0usize;
        let mut scanned_files = 0usize;
        let mut total = 0u64;
        for entry in workspaces.entries()? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            workspace_count += 1;
            if workspace_count > MAX_CACHED_WORKSPACES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many cached workspaces to count sync recovery bodies",
                ));
            }
            let content = self
                .path
                .join("workspaces")
                .join(entry.file_name())
                .join("content");
            let names = match self.regular_file_names(
                &content,
                MAX_FILES_PER_WORKSPACE,
                MAX_FILENAME_BYTES,
            ) {
                Ok(names) => names,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            scanned_files = scanned_files.checked_add(names.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sync recovery scan entry count overflowed",
                )
            })?;
            if scanned_files > MAX_SCANNED_FILES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many cached files to count sync recovery bodies",
                ));
            }
            for name in names {
                if name.as_encoded_bytes().ends_with(RECOVERY_SUFFIX) {
                    let body = SafeCacheInput::open(self, &content.join(Path::new(&name)))?;
                    total = total.checked_add(body.length()).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sync recovery byte count overflowed",
                        )
                    })?;
                }
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::sync_client_fs::{ensure_cache_directory, ensure_cache_root, SafeDownloadTarget};

    use super::*;

    #[test]
    fn counts_recovery_bodies_across_cached_workspaces() {
        #[cfg(unix)]
        let fixture = crate::sync_client_fs::unix_test_support::private_tempdir();
        #[cfg(not(unix))]
        let fixture = tempfile::tempdir().unwrap();
        let cache = ensure_cache_root(&fixture.path().join("cache")).unwrap();
        for (workspace, leaf, body) in [
            ("first", "one.local-abc.remote-conflict", b"abc".as_slice()),
            (
                "second",
                "two.remote-r1-abc.remote-conflict",
                b"hello".as_slice(),
            ),
            ("second", "normal", b"ordinary".as_slice()),
        ] {
            let content = ensure_cache_directory(
                &cache,
                &Path::new("workspaces").join(workspace).join("content"),
            )
            .unwrap();
            let mut target = SafeDownloadTarget::begin(&cache, &content.join(leaf)).unwrap();
            target.file_mut().write_all(body).unwrap();
            target.commit_new().unwrap();
        }
        assert_eq!(cache.retained_recovery_bytes().unwrap(), 8);
    }
}

use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context};
use uuid::Uuid;

use crate::{
    model::DriveFile,
    sync_client_fs::{SafeCacheRoot, SafeLocalSnapshot},
};

use super::{budget::SyncPassBudget, MAX_SYNC_DOWNLOAD_BYTES, REMOTE_CONFLICT_SUFFIX};

pub(super) enum DownloadPublication {
    New,
    TrackedReplacement {
        expected_local_hash: String,
        retained_local_bytes: u64,
    },
}

pub(super) enum DownloadPublicationOutcome {
    Published,
    PreservedChangedLocal,
}

pub(super) enum PreparedPublication {
    New,
    Tracked {
        displaced_path: Option<PathBuf>,
        expected_local_hash: String,
        estimated_local_bytes: u64,
    },
}

pub(super) fn remote_conflict_path(
    content_dir: &Path,
    file: &DriveFile,
) -> anyhow::Result<PathBuf> {
    let hash = file
        .content_hash
        .as_deref()
        .context("sync manifest omitted the remote content hash")?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("sync manifest reported an invalid remote content hash");
    }
    Ok(content_dir.join(format!(
        "{}.remote-r{}-{}{}",
        file.id,
        file.revision,
        hash.to_ascii_lowercase(),
        REMOTE_CONFLICT_SUFFIX
    )))
}

pub(super) fn existing_remote_conflict_is_current(
    cache_root: &SafeCacheRoot,
    path: &Path,
    expected_hash: &str,
    max_bytes: u64,
) -> anyhow::Result<bool> {
    match SafeLocalSnapshot::open(cache_root, path, max_bytes) {
        Ok(snapshot) if snapshot.hash() == expected_hash => Ok(true),
        Ok(_) => bail!(
            "reserved remote-conflict path contains different local bytes: {}",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn prepare(
    cache_root: &SafeCacheRoot,
    destination: &Path,
    publication: DownloadPublication,
) -> anyhow::Result<PreparedPublication> {
    let DownloadPublication::TrackedReplacement {
        expected_local_hash,
        retained_local_bytes,
    } = publication
    else {
        return Ok(PreparedPublication::New);
    };

    let parent = destination
        .parent()
        .context("tracked download destination has no parent")?;
    let leaf = destination
        .file_name()
        .context("tracked download destination has no filename")?
        .to_string_lossy();
    let displaced_path = parent.join(format!(
        "{leaf}.local-{}{}",
        Uuid::new_v4().simple(),
        REMOTE_CONFLICT_SUFFIX
    ));
    match cache_root.rename_new(destination, &displaced_path) {
        Ok(()) => Ok(PreparedPublication::Tracked {
            displaced_path: Some(displaced_path),
            expected_local_hash,
            estimated_local_bytes: retained_local_bytes,
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(PreparedPublication::Tracked {
            displaced_path: None,
            expected_local_hash,
            estimated_local_bytes: retained_local_bytes,
        }),
        Err(error) => Err(error.into()),
    }
}

/// The original reservation was made before an asynchronous download. Admit
/// the actual local body after its atomic move and before publishing remote
/// bytes; restore it if the retained-body limit would be exceeded.
pub(super) fn admit_prepared(
    cache_root: &SafeCacheRoot,
    destination: &Path,
    prepared: &PreparedPublication,
    budget: &mut SyncPassBudget,
) -> anyhow::Result<()> {
    let PreparedPublication::Tracked {
        displaced_path,
        estimated_local_bytes,
        ..
    } = prepared
    else {
        return Ok(());
    };
    let Some(path) = displaced_path else {
        return budget.adjust_recovery_reservation(*estimated_local_bytes, 0);
    };
    let admission = (|| -> anyhow::Result<()> {
        let actual_bytes = cache_root.regular_file_len(path)?;
        if actual_bytes > MAX_SYNC_DOWNLOAD_BYTES {
            bail!(
                "changed local body exceeds the {}-byte sync file limit",
                MAX_SYNC_DOWNLOAD_BYTES
            );
        }
        budget.adjust_recovery_reservation(*estimated_local_bytes, actual_bytes)
    })();
    if let Err(error) = admission {
        if let Err(restore_error) = cache_root.rename_new(path, destination) {
            bail!(
                "{error}; could not restore the local body to {}: {restore_error}; recovery body remains at {}",
                destination.display(),
                path.display()
            );
        }
        return Err(error);
    }
    Ok(())
}

pub(super) fn finish(
    cache_root: &SafeCacheRoot,
    prepared: PreparedPublication,
) -> anyhow::Result<DownloadPublicationOutcome> {
    let PreparedPublication::Tracked {
        displaced_path,
        expected_local_hash,
        ..
    } = prepared
    else {
        return Ok(DownloadPublicationOutcome::Published);
    };
    let Some(displaced_path) = displaced_path else {
        return Ok(DownloadPublicationOutcome::Published);
    };
    let displaced = match SafeLocalSnapshot::open(
        cache_root,
        &displaced_path,
        super::MAX_SYNC_DOWNLOAD_BYTES,
    ) {
        Ok(displaced) => displaced,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(DownloadPublicationOutcome::Published);
        }
        Err(error) => return Err(error.into()),
    };
    // There is no portable compare-and-unlink primitive. Retain even an
    // unchanged displaced body: deleting it after a hash check would let a
    // same-user writer replace or edit the recovery leaf in the final window.
    if displaced.hash() == expected_local_hash {
        Ok(DownloadPublicationOutcome::Published)
    } else {
        Ok(DownloadPublicationOutcome::PreservedChangedLocal)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use sha2::{Digest, Sha256};

    use crate::sync_client_fs::{ensure_cache_directory, ensure_cache_root, SafeDownloadTarget};

    use super::*;

    fn hash(body: &[u8]) -> String {
        hex::encode(Sha256::digest(body))
    }

    fn private_tempdir() -> tempfile::TempDir {
        #[cfg(unix)]
        {
            crate::sync_client_fs::unix_test_support::private_tempdir()
        }
        #[cfg(not(unix))]
        {
            tempfile::tempdir().unwrap()
        }
    }

    fn write_private_leaf(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        crate::fs_private::set_file_private(path).unwrap();
    }

    #[test]
    fn tracked_replacement_preserves_a_changed_local_leaf() {
        let fixture = private_tempdir();
        let cache = ensure_cache_root(&fixture.path().join("cache")).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("content")).unwrap();
        let destination = content.join("remote-id");
        write_private_leaf(&destination, b"changed local");
        let mut target = SafeDownloadTarget::begin(&cache, &destination).unwrap();
        target.file_mut().write_all(b"verified remote").unwrap();

        let prepared = prepare(
            &cache,
            &destination,
            DownloadPublication::TrackedReplacement {
                expected_local_hash: hash(b"old baseline"),
                retained_local_bytes: b"old baseline".len() as u64,
            },
        )
        .unwrap();
        target.commit_new().unwrap();
        let recovery_path = match &prepared {
            PreparedPublication::Tracked {
                displaced_path: Some(path),
                ..
            } => path.clone(),
            _ => panic!("changed local bytes must have a recovery path"),
        };
        let outcome = finish(&cache, prepared).unwrap();

        let DownloadPublicationOutcome::PreservedChangedLocal = outcome else {
            panic!("changed local bytes must be preserved");
        };
        assert_eq!(std::fs::read(destination).unwrap(), b"verified remote");
        assert_eq!(std::fs::read(recovery_path).unwrap(), b"changed local");
    }

    #[test]
    fn tracked_replacement_retains_the_unchanged_prior_body() {
        let fixture = private_tempdir();
        let cache = ensure_cache_root(&fixture.path().join("cache")).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("content")).unwrap();
        let destination = content.join("remote-id");
        write_private_leaf(&destination, b"old baseline");
        let mut target = SafeDownloadTarget::begin(&cache, &destination).unwrap();
        target.file_mut().write_all(b"verified remote").unwrap();

        let prepared = prepare(
            &cache,
            &destination,
            DownloadPublication::TrackedReplacement {
                expected_local_hash: hash(b"old baseline"),
                retained_local_bytes: b"old baseline".len() as u64,
            },
        )
        .unwrap();
        target.commit_new().unwrap();
        assert!(matches!(
            finish(&cache, prepared).unwrap(),
            DownloadPublicationOutcome::Published
        ));
        assert_eq!(std::fs::read(destination).unwrap(), b"verified remote");
        let retained = cache.regular_file_names(&content, 8, 1024).unwrap();
        assert_eq!(retained.len(), 2);
        assert!(retained.iter().any(|name| {
            name.to_string_lossy().starts_with("remote-id.local-")
                && name.to_string_lossy().ends_with(REMOTE_CONFLICT_SUFFIX)
        }));
    }

    #[test]
    fn tracked_replacement_never_deletes_a_recovery_leaf_changed_after_prepare() {
        let fixture = private_tempdir();
        let cache = ensure_cache_root(&fixture.path().join("cache")).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("content")).unwrap();
        let destination = content.join("remote-id");
        write_private_leaf(&destination, b"old baseline");
        let mut target = SafeDownloadTarget::begin(&cache, &destination).unwrap();
        target.file_mut().write_all(b"verified remote").unwrap();

        let prepared = prepare(
            &cache,
            &destination,
            DownloadPublication::TrackedReplacement {
                expected_local_hash: hash(b"old baseline"),
                retained_local_bytes: b"old baseline".len() as u64,
            },
        )
        .unwrap();
        let recovery_path = match &prepared {
            PreparedPublication::Tracked {
                displaced_path: Some(path),
                ..
            } => path.clone(),
            _ => panic!("tracked replacement must retain a recovery path"),
        };
        target.commit_new().unwrap();
        std::fs::write(&recovery_path, b"late local edit").unwrap();

        assert!(matches!(
            finish(&cache, prepared).unwrap(),
            DownloadPublicationOutcome::PreservedChangedLocal
        ));
        assert_eq!(std::fs::read(destination).unwrap(), b"verified remote");
        assert_eq!(std::fs::read(recovery_path).unwrap(), b"late local edit");
    }

    #[test]
    fn changed_local_body_over_recovery_cap_is_restored_before_remote_publication() {
        let fixture = private_tempdir();
        let cache = ensure_cache_root(&fixture.path().join("cache")).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("content")).unwrap();
        let destination = content.join("remote-id");
        write_private_leaf(&destination, b"changed-ten");
        let mut budget = SyncPassBudget::new(super::super::SyncPassLimits::default());
        budget
            .reserve_recovery(&cache, 4 * 1024 * 1024 * 1024 - 5)
            .unwrap();
        budget.reserve_recovery(&cache, 1).unwrap();
        let prepared = prepare(
            &cache,
            &destination,
            DownloadPublication::TrackedReplacement {
                expected_local_hash: hash(b"original"),
                retained_local_bytes: 1,
            },
        )
        .unwrap();
        let error = admit_prepared(&cache, &destination, &prepared, &mut budget).unwrap_err();
        assert!(error.to_string().contains("retained sync recovery bodies"));
        assert_eq!(std::fs::read(&destination).unwrap(), b"changed-ten");
        assert_eq!(
            cache.regular_file_names(&content, 8, 1024).unwrap().len(),
            1
        );
    }
}

//! Native regressions for handle-bound inbound file replacement.

use std::{
    fs,
    io::Write,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use super::*;
use super::{
    replacement_guard::{publish_replacing_staged_file, FrozenDestination, ReplacementOutcome},
    verified_staging::VerifiedStagedFile,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "shellx-drive-replacement-{label}-{}-{}",
            process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::AcqRel)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn staged_payload(
    root: &Path,
    bytes: &[u8],
) -> (OwnedStagingRoot, PathBuf, PathBuf, VerifiedStagedFile) {
    let staging_root = download_staging_root(root).unwrap();
    let (area, batch) = create_owned_staging_batch(root, &staging_root, "download").unwrap();
    let staged = batch.join("payload");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .access_mode(
            windows_sys::Win32::Foundation::GENERIC_READ
                | windows_sys::Win32::Foundation::GENERIC_WRITE
                | windows_sys::Win32::Storage::FileSystem::DELETE
                | windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES,
        )
        .create_new(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&staged)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    (area, batch, staged, VerifiedStagedFile(file))
}

#[test]
fn frozen_destination_blocks_the_final_writer_window() {
    let parent = TestDirectory::new("late-writer");
    let root = parent.0.join("pair");
    fs::create_dir(&root).unwrap();
    let destination = root.join("report.bin");
    fs::write(&destination, b"baseline").unwrap();
    let (area, batch, staged, verified) = staged_payload(&root, b"remote-body");
    let mut budget = local_read_budget_for_sync_pass();
    let frozen =
        FrozenDestination::open(&root, &destination, Path::new("report.bin"), &mut budget).unwrap();
    let expected = DownloadPrecondition::ExactLocal {
        content_hash: frozen.entry().content_hash.clone(),
        size_bytes: frozen.entry().size_bytes,
        is_directory: false,
    };
    assert!(download_precondition_matches(
        &expected,
        Some(frozen.entry())
    ));

    let outcome = publish_replacing_staged_file(
        &root,
        &destination,
        &staged,
        &verified,
        Some((&area, &batch)),
        frozen,
        || {
            assert!(fs::OpenOptions::new()
                .write(true)
                .share_mode(
                    windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                        | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
                        | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
                )
                .open(&destination)
                .is_err());
            assert!(fs::rename(&destination, root.join("attacker.bin")).is_err());
            Ok(())
        },
        || Ok(()),
    )
    .unwrap();
    assert!(matches!(outcome, ReplacementOutcome::Published));
    assert_eq!(fs::read(&destination).unwrap(), b"remote-body");
    assert_eq!(
        fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("replaced"))
            .count(),
        0
    );
    drop(verified);
    retire_owned_staging_batch(&area, &batch).unwrap();
}

#[test]
fn an_existing_writer_forces_review_before_any_mutation() {
    let parent = TestDirectory::new("existing-writer");
    let root = parent.0.join("pair");
    fs::create_dir(&root).unwrap();
    let destination = root.join("report.bin");
    fs::write(&destination, b"baseline").unwrap();
    let writer = fs::OpenOptions::new()
        .write(true)
        .share_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
        )
        .open(&destination)
        .unwrap();
    let mut budget = local_read_budget_for_sync_pass();
    assert!(
        FrozenDestination::open(&root, &destination, Path::new("report.bin"), &mut budget).is_err()
    );
    assert_eq!(fs::read(&destination).unwrap(), b"baseline");
    drop(writer);
}

#[test]
fn a_late_leaf_collision_preserves_all_available_bodies() {
    let parent = TestDirectory::new("late-leaf");
    let root = parent.0.join("pair");
    fs::create_dir(&root).unwrap();
    let destination = root.join("report.bin");
    fs::write(&destination, b"baseline").unwrap();
    let (area, batch, staged, verified) = staged_payload(&root, b"remote-body");
    let mut budget = local_read_budget_for_sync_pass();
    let frozen =
        FrozenDestination::open(&root, &destination, Path::new("report.bin"), &mut budget).unwrap();

    let outcome = publish_replacing_staged_file(
        &root,
        &destination,
        &staged,
        &verified,
        Some((&area, &batch)),
        frozen,
        || Ok(()),
        || {
            fs::write(&destination, b"late-local")?;
            Ok(())
        },
    )
    .unwrap();
    let ReplacementOutcome::NeedsReview {
        recovery_leaf: Some(recovery_leaf),
    } = outcome
    else {
        panic!("late collision must retain an explicit recovery leaf")
    };
    assert_eq!(fs::read(&destination).unwrap(), b"late-local");
    assert_eq!(fs::read(root.join(recovery_leaf)).unwrap(), b"baseline");
    assert_eq!(fs::read(&staged).unwrap(), b"remote-body");
    assert!(area.remove_batch(&batch).is_err());
    drop(verified);
}

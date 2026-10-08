//! Native NTFS hard-link boundary coverage for upload and replacement sinks.

use std::{fs, path::Path};

use shellx_drive_desktop_core::DesktopError;

use super::{replacement_guard::FrozenDestination, *};

fn is_unsafe_link<T>(result: CoreResult<T>) -> bool {
    matches!(result, Err(DesktopError::UnsafeLink(_)))
}

#[test]
fn upload_and_replacement_handles_reject_an_ntfs_hard_link() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("pair");
    fs::create_dir(&root).unwrap();
    let outside = fixture.path().join("outside.txt");
    let inside = root.join("inside.txt");
    fs::write(&outside, b"shared NTFS object").unwrap();
    fs::hard_link(&outside, &inside).unwrap();

    assert!(is_unsafe_link(open_checked_upload_source(&root, &inside)));

    let mut upload_budget = local_read_budget_for_sync_pass();
    let Err(snapshot_error) =
        snapshot_upload_source(&root, Path::new("inside.txt"), &mut upload_budget)
    else {
        panic!("hard-linked upload source was accepted");
    };
    assert!(matches!(snapshot_error, DesktopError::UnsafeLink(_)));
    assert!(matches!(
        upload_snapshot_failure_review(Path::new("inside.txt"), &snapshot_error),
        ReviewItem {
            kind: ReviewKind::UnsafeLink,
            ..
        }
    ));

    let mut replacement_budget = local_read_budget_for_sync_pass();
    assert!(is_unsafe_link(FrozenDestination::open(
        &root,
        &inside,
        Path::new("inside.txt"),
        &mut replacement_budget,
    )));
}

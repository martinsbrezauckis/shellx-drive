use std::{fs, path::Path};

use shellx_drive_desktop_core::{inspect_local_tree, PairMarker};

use super::*;
use crate::platform::unix::filesystem::{test_fixture_directory, UnixRootGuard};

#[test]
fn marker_removed_after_snapshot_blocks_upload_and_cleans_owned_batch() {
    let temporary = test_fixture_directory();
    let root = temporary.path().join("Drive");
    fs::create_dir(&root).expect("create root");
    fs::write(root.join("report.txt"), b"local bytes").expect("create local file");
    let guard = UnixRootGuard::acquire(&root, None).expect("guard root");
    let pair = SyncPair {
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        local_root: root.clone(),
        local_root_identity: Some(guard.identity().clone()),
        remote_root_id: None,
        remote_root_name: None,
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
    };
    let marker = PairMarker::from(&pair);
    guard
        .write_or_recognize_pair_marker(&marker)
        .expect("install exact marker");
    let planned = inspect_local_tree(&root)
        .expect("scan local file")
        .entries
        .into_iter()
        .find(|entry| entry.relative_path == Path::new("report.txt"))
        .expect("planned local file");
    let snapshot = upload_snapshot(&guard, &pair, Path::new("report.txt"), &planned)
        .expect("private upload snapshot");
    let (owned, batch, file, _) = snapshot.into_parts();
    guard
        .remove_exact_pair_marker(&marker)
        .expect("remove marker after snapshot");

    assert!(require_terminal_upload_marker(&guard, &pair, &owned, &batch).is_err());
    drop(file);
    assert!(!batch.exists(), "rejected upload must remove its batch");
    assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"local bytes");
}

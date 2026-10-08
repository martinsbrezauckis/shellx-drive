use std::path::Path;

use shellx_drive_desktop_core::SyncPair;

use super::*;

#[test]
fn marker_rollback_never_deletes_the_selected_base() {
    let directory = tempfile::tempdir().expect("temp directory");
    let base = directory.path().join("Drive");
    std::fs::create_dir(&base).expect("base");
    let base_guard = UnixRootGuard::acquire(&base, None).expect("base guard");
    base_guard
        .ensure_directory(Path::new("My files"))
        .expect("root directory");
    let root = base.join("My files");
    let guard = UnixRootGuard::acquire(&root, None).expect("root guard");
    let pair = SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "My files".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: root.clone(),
        local_root_identity: Some(guard.identity().clone()),
    };
    guard
        .write_or_recognize_pair_marker(&PairMarker::from(&pair))
        .expect("marker");
    rollback_created_markers(&[pair]);
    assert!(base.is_dir());
    assert!(root.is_dir());
    assert!(!root.join(".shellx-drive-pair.json").exists());
}

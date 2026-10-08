use super::*;

#[test]
fn initial_child_root_binding_rejects_a_replaced_directory() {
    let directory = test_fixture_directory();
    let base = directory.path().join("Drive");
    fs::create_dir(&base).unwrap();
    let guard = UnixRootGuard::acquire(&base, None).unwrap();
    let child = base.join("My files");
    let displaced = base.join("displaced");

    let result = super::super::descriptor::ensure_child_root_with_hook(
        &guard,
        Path::new("My files"),
        || {
            fs::rename(&child, &displaced).unwrap();
            fs::create_dir(&child).unwrap();
            fs::write(child.join("keep.txt"), b"unrelated local data").unwrap();
        },
    );

    assert!(result.is_err());
    assert_eq!(
        fs::read(child.join("keep.txt")).unwrap(),
        b"unrelated local data"
    );
    assert!(!child.join(PAIR_MARKER_FILE).exists());
    assert!(!displaced.join(PAIR_MARKER_FILE).exists());
}

#[test]
fn initial_child_root_stays_bound_to_selected_base_and_preserves_empty_rule() {
    let directory = test_fixture_directory();
    let base = directory.path().join("Drive");
    fs::create_dir(&base).unwrap();
    let guard = UnixRootGuard::acquire(&base, None).unwrap();
    let child = guard
        .ensure_child_root(Path::new("Shared with me/Avery"))
        .unwrap();
    child.ensure_empty_root().unwrap();
    assert_eq!(
        child.identity(),
        &guard
            .local_directory_identity(Path::new("Shared with me/Avery"))
            .unwrap()
    );
    let marker = PairMarker {
        schema_version: 2,
        workspace_id: "workspace".to_string(),
        remote_root_id: Some("shared-root".to_string()),
        server_url: "https://drive.example.test".to_string(),
        local_root_identity: Some(child.identity().clone()),
    };
    assert_eq!(
        child.write_or_recognize_pair_marker(&marker).unwrap(),
        PairMarkerDisposition::Created
    );
    child.ensure_empty_root().unwrap();
    assert!(!base.join(PAIR_MARKER_FILE).exists());
    fs::write(base.join("Shared with me/Avery/keep.txt"), b"user data").unwrap();
    assert!(child.ensure_empty_root().is_err());
}

#[test]
fn initial_pair_marker_is_removed_if_child_moves_during_publication() {
    let directory = test_fixture_directory();
    let base = directory.path().join("Drive");
    fs::create_dir(&base).unwrap();
    let guard = UnixRootGuard::acquire(&base, None).unwrap();
    let relative = Path::new("My files");
    let child = guard.ensure_child_root(relative).unwrap();
    let configured = base.join(relative);
    let displaced = base.join("displaced");
    let marker = PairMarker {
        schema_version: 2,
        workspace_id: "workspace".to_string(),
        remote_root_id: None,
        server_url: "https://drive.example.test".to_string(),
        local_root_identity: Some(child.identity().clone()),
    };

    let result = super::super::descriptor::write_or_recognize_child_pair_marker_with_hook(
        &guard,
        relative,
        &child,
        &marker,
        || {
            fs::rename(&configured, &displaced).unwrap();
            fs::create_dir(&configured).unwrap();
            fs::write(configured.join("keep.txt"), b"replacement").unwrap();
        },
    );

    assert!(result.is_err());
    assert!(!displaced.join(PAIR_MARKER_FILE).exists());
    assert!(!configured.join(PAIR_MARKER_FILE).exists());
    assert_eq!(
        fs::read(configured.join("keep.txt")).unwrap(),
        b"replacement"
    );
}

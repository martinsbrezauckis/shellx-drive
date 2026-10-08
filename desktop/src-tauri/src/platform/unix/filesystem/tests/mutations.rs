use super::*;
use crate::platform::unix::filesystem::test_fixture_directory;
#[cfg(target_os = "linux")]
use crate::platform::unix::filesystem::ReplacingPublication;
use std::os::unix::fs::PermissionsExt;

#[test]
fn regular_descriptor_open_rejects_a_fifo_without_waiting_for_a_writer() {
    use std::{ffi::CString, io::Read, os::unix::ffi::OsStrExt, sync::mpsc, time::Duration};

    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("regular.txt"), b"regular bytes").unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    let mut bytes = String::new();
    guard
        .open_regular_file(Path::new("regular.txt"))
        .unwrap()
        .read_to_string(&mut bytes)
        .unwrap();
    assert_eq!(bytes, "regular bytes");
    let fifo = root.join("changed-leaf");
    let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        sender
            .send(
                guard
                    .open_regular_file(Path::new("changed-leaf"))
                    .map(|_| ()),
            )
            .unwrap();
    });
    let result = receiver.recv_timeout(Duration::from_secs(1));
    // If the opener regresses, release it before failing instead of leaving
    // a blocked test thread behind.
    let release = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    worker.join().unwrap();
    drop(release);
    assert!(matches!(
        result.expect("FIFO open must not wait for a writer"),
        Err(shellx_drive_desktop_core::DesktopError::UnsafePath(_))
    ));
}

#[test]
fn compatible_destination_rejects_a_case_alias_but_allows_the_rename_source() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("Source.txt"), b"source").unwrap();
    fs::write(root.join("REPORT.txt"), b"occupied").unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();

    assert!(!guard
        .compatible_destination_is_absent(Path::new("report.txt"), Some(Path::new("Source.txt")),)
        .unwrap());
    assert!(guard
        .compatible_destination_is_absent(Path::new("source.txt"), Some(Path::new("Source.txt")),)
        .unwrap());
}

#[test]
fn replacement_preparation_never_adopts_a_post_plan_local_body() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    let staging = directory.path().join("private");
    fs::create_dir(&root).unwrap();
    shellx_drive_desktop_core::ensure_private_staging_directory(&staging).unwrap();
    fs::write(root.join("report.txt"), b"baseline").unwrap();
    let staged = staging.join("payload");
    fs::write(&staged, b"remote").unwrap();
    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&staged, permissions).unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    let expected = guard.local_regular_entry(Path::new("report.txt")).unwrap();
    fs::write(root.join("report.txt"), b"post-plan-edit").unwrap();

    assert!(guard
        .prepare_staged_file_replacement(&staged, Path::new("report.txt"), &expected)
        .unwrap()
        .is_none());
    assert_eq!(
        fs::read(root.join("report.txt")).unwrap(),
        b"post-plan-edit"
    );
    assert_eq!(fs::read(staged).unwrap(), b"remote");
    assert!(!staging.join("local-recovery").exists());
}

#[test]
#[cfg(target_os = "linux")]
fn replacement_keeps_a_late_local_edit_in_recovery_instead_of_silently_overwriting_it() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    let staging = directory.path().join("private");
    fs::create_dir(&root).unwrap();
    shellx_drive_desktop_core::ensure_private_staging_directory(&staging).unwrap();
    fs::write(root.join("report.txt"), b"baseline").unwrap();
    let staged = staging.join("payload");
    let mut staged_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .unwrap();
    use std::io::Write;
    staged_file.write_all(b"remote").unwrap();
    drop(staged_file);
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    let expected = guard.local_regular_entry(Path::new("report.txt")).unwrap();

    let prepared = guard
        .prepare_staged_file_replacement(&staged, Path::new("report.txt"), &expected)
        .unwrap()
        .expect("unchanged local body prepares a private recovery copy");
    let scanned = shellx_drive_desktop_core::inspect_local_tree(&root).unwrap();
    assert_eq!(scanned.entries.len(), 1);
    assert_eq!(scanned.entries[0].relative_path, Path::new("report.txt"));

    let outcome = prepared
        .publish(&guard, || {
            fs::write(root.join("report.txt"), b"late-local-edit").unwrap();
            Ok(())
        })
        .unwrap();

    let ReplacingPublication::NeedsReview {
        recovery_leaf: None,
    } = outcome
    else {
        panic!("a post-check edit must retain a recovery body");
    };
    // The edit is detected before exchange, so the selected root keeps the
    // newer local body. Both the preserved original and remote staged body
    // remain available for review rather than overwriting either one.
    assert_eq!(
        fs::read(root.join("report.txt")).unwrap(),
        b"late-local-edit"
    );
    assert_eq!(
        fs::read(staging.join("local-recovery")).unwrap(),
        b"baseline"
    );
    assert_eq!(fs::read(staged).unwrap(), b"remote");
    assert!(fs::read_dir(&root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".shellx-drive-replaced-")
    }));
}

#[test]
#[cfg(target_os = "linux")]
fn replacement_publishes_remote_body_only_with_a_retained_local_recovery() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    let staging = directory.path().join("private");
    fs::create_dir(&root).unwrap();
    shellx_drive_desktop_core::ensure_private_staging_directory(&staging).unwrap();
    fs::write(root.join("report.txt"), b"baseline").unwrap();
    let staged = staging.join("payload");
    let mut staged_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .unwrap();
    use std::io::Write;
    staged_file.write_all(b"remote").unwrap();
    drop(staged_file);
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    let expected = guard.local_regular_entry(Path::new("report.txt")).unwrap();

    assert_eq!(
        guard
            .prepare_staged_file_replacement(&staged, Path::new("report.txt"), &expected)
            .unwrap()
            .expect("unchanged local body prepares a private recovery copy")
            .publish(&guard, || Ok(()))
            .unwrap(),
        ReplacingPublication::Published
    );
    assert_eq!(fs::read(root.join("report.txt")).unwrap(), b"remote");
    assert_eq!(fs::read(&staged).unwrap(), b"baseline");
    assert_eq!(
        fs::read(staging.join("local-recovery")).unwrap(),
        b"baseline"
    );
    assert!(fs::read_dir(&root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".shellx-drive-replaced-")
    }));
}

#[test]
fn no_replace_move_refuses_a_destination_created_after_revalidation() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("old.txt"), b"tracked").unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();

    assert!(guard
        .move_entry_noreplace(Path::new("old.txt"), Path::new("new.txt"), false, || {
            fs::write(root.join("new.txt"), b"racing-user-file").unwrap();
            Ok(())
        },)
        .is_err());
    assert_eq!(fs::read(root.join("old.txt")).unwrap(), b"tracked");
    assert_eq!(fs::read(root.join("new.txt")).unwrap(), b"racing-user-file");
}

#[test]
fn complete_root_recovery_moves_instead_of_recursively_deleting_user_bytes() {
    let directory = test_fixture_directory();
    let root = directory.path().join("Drive");
    let recovery_batch = directory.path().join("recovery-batch");
    fs::create_dir(&root).unwrap();
    shellx_drive_desktop_core::ensure_private_staging_directory(&recovery_batch).unwrap();
    fs::write(root.join("keep.txt"), b"user bytes").unwrap();
    let guard = UnixRootGuard::acquire(&root, None).unwrap();
    let marker = PairMarker {
        schema_version: 2,
        workspace_id: "workspace".to_string(),
        remote_root_id: None,
        server_url: "https://drive.example.test".to_string(),
        local_root_identity: Some(guard.identity().clone()),
    };
    guard.write_or_recognize_pair_marker(&marker).unwrap();
    let destination = recovery_batch.join("Drive");

    guard
        .move_complete_root_to_recovery(&marker, &destination, || {
            guard.require_exact_pair_marker(&marker)
        })
        .unwrap();
    assert!(!root.exists());
    assert_eq!(
        fs::read(destination.join("keep.txt")).unwrap(),
        b"user bytes"
    );
    let recovered =
        UnixRootGuard::acquire(&destination, marker.local_root_identity.as_ref()).unwrap();
    recovered.require_exact_pair_marker(&marker).unwrap();
}

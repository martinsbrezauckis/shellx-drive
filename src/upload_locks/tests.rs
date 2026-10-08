use super::*;

#[test]
fn v1_mapping_is_stable_for_both_identifier_families() {
    let directory = Path::new("staging");
    assert_eq!(
        stripe_path(directory, "00000000-0000-0000-0000-000000000000"),
        directory.join("lock-v1-2b9.lock")
    );
    assert_eq!(
        stripe_path(directory, &"a".repeat(64)),
        directory.join("lock-v1-3e0.lock")
    );
}

fn collision_pair(directory: &Path) -> (String, String) {
    let mut seen = std::collections::HashMap::new();
    for value in 0..=STRIPE_COUNT as u128 {
        let id = uuid::Uuid::from_u128(value).to_string();
        if let Some(previous) = seen.insert(stripe_path(directory, &id), id.clone()) {
            return (previous, id);
        }
    }
    unreachable!("more identifiers than stripes must collide")
}

#[test]
fn distinct_sessions_leave_at_most_1024_locks_in_each_directory() {
    let data = tempfile::tempdir().unwrap();
    for directory in [
        data.path().join("uploads"),
        data.path().join("drop-uploads"),
    ] {
        std::fs::create_dir(&directory).unwrap();
        for value in 0..(STRIPE_COUNT * 8) as u128 {
            let id = if directory.ends_with("uploads") {
                uuid::Uuid::from_u128(value).to_string()
            } else {
                format!("{value:064x}")
            };
            drop(UploadSessionLock::acquire(&directory, &id).unwrap());
            assert!(!directory.join(format!("{id}.lock")).exists());
        }
        let entries = std::fs::read_dir(&directory)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(entries.len() <= STRIPE_COUNT);
        assert!(entries.iter().all(|entry| entry
            .file_name()
            .to_str()
            .unwrap()
            .starts_with("lock-v1-")));
    }
}

#[test]
fn same_session_and_collision_are_busy_until_released_without_cross_directory_contention() {
    let data = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let (one, two) = collision_pair(data.path());
    let held = UploadSessionLock::acquire(data.path(), &one).unwrap();
    for id in [&one, &two] {
        assert!(matches!(
            UploadSessionLock::acquire(data.path(), id),
            Err(ApiError::Conflict)
        ));
    }
    let _independent = UploadSessionLock::acquire(other.path(), &one).unwrap();
    drop(held);
    let _retried = UploadSessionLock::acquire(data.path(), &two).unwrap();
}

#[test]
fn legacy_contention_releases_the_stripe_and_preserves_the_legacy_inode() {
    let data = tempfile::tempdir().unwrap();
    let (one, two) = collision_pair(data.path());
    let path = data.path().join(format!("{one}.lock"));
    std::fs::write(&path, b"legacy lock identity").unwrap();
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt as _;
        path.metadata().unwrap().ino()
    };
    let legacy = open_lock(&path, false).unwrap();
    assert!(matches!(
        UploadSessionLock::acquire(data.path(), &one),
        Err(ApiError::Conflict)
    ));
    // Legacy acquisition failed after stripe acquisition. The colliding ID
    // proves that failure released the stripe rather than poisoning it.
    drop(UploadSessionLock::acquire(data.path(), &two).unwrap());
    drop(legacy);
    let reacquired = UploadSessionLock::acquire(data.path(), &one).unwrap();
    assert!(reacquired._legacy_file.is_some());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(path.metadata().unwrap().ino(), inode);
        assert_eq!(
            reacquired._stripe_file.0.metadata().unwrap().mode() & 0o777,
            0o600
        );
    }
    drop(reacquired);
    assert_eq!(std::fs::read(&path).unwrap(), b"legacy lock identity");
}

#[test]
fn unsafe_identifiers_create_no_lock_files() {
    let data = tempfile::tempdir().unwrap();
    for id in ["../escape", "not-a-session", "A".repeat(64).as_str()] {
        assert!(UploadSessionLock::acquire(data.path(), id).is_err());
    }
    assert_eq!(std::fs::read_dir(data.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn subprocess_lock_probe() {
    let Some(directory) = std::env::var_os("SHELLX_UPLOAD_LOCK_TEST_DIRECTORY") else {
        return;
    };
    let id = std::env::var("SHELLX_UPLOAD_LOCK_TEST_ID").unwrap();
    let busy = std::env::var("SHELLX_UPLOAD_LOCK_TEST_BUSY").unwrap() == "true";
    let result = UploadSessionLock::acquire(Path::new(&directory), &id);
    if busy {
        assert!(matches!(result, Err(ApiError::Conflict)));
    } else {
        assert!(result.is_ok());
    }
}

#[cfg(unix)]
#[test]
fn separate_processes_contend_on_the_same_persistent_stripe() {
    let data = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let held = UploadSessionLock::acquire(data.path(), &id).unwrap();
    let probe = |busy: bool| {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "upload_locks::tests::subprocess_lock_probe",
                "--nocapture",
            ])
            .env("SHELLX_UPLOAD_LOCK_TEST_DIRECTORY", data.path())
            .env("SHELLX_UPLOAD_LOCK_TEST_ID", &id)
            .env("SHELLX_UPLOAD_LOCK_TEST_BUSY", busy.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    probe(true);
    drop(held);
    probe(false);
}

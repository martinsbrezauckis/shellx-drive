use std::{os::unix::fs::PermissionsExt, process::Command, time::Duration};

use super::*;

#[test]
fn quoted_exec_preserves_special_path_characters_in_the_native_launcher() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory
        .path()
        .join("Drive's \"quoted\" $cash `tick` \\ path 雲");
    let marker = PathBuf::from(format!("{}.marker", executable.display()));
    fs::write(&executable, b"#!/bin/sh\nprintf launched > \"$0.marker\"\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let entry = directory.path().join("drive.desktop");
    fs::write(&entry, autostart_contents_for(&executable).unwrap()).unwrap();
    let output = Command::new("gio")
        .arg("launch")
        .arg(&entry)
        .output()
        .expect("Linux desktop tests require the native GLib gio launcher");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fs::read_to_string(marker).unwrap(), "launched");
}

#[test]
fn unsupported_exec_paths_are_rejected_without_lossy_conversion() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    for path in ["/Drive=other", "/Drive%f", "/Drive\nother", "/Drive\tother"] {
        assert!(autostart_contents_for(Path::new(path)).is_err());
    }
    let path = PathBuf::from(OsString::from_vec(b"/Drive\xff".to_vec()));
    assert!(autostart_contents_for(&path).is_err());
}

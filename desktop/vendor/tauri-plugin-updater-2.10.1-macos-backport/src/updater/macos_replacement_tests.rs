// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use std::{fs, path::Path, process::Command};

use super::{
    macos_privileged_replacement_arguments, macos_privileged_staging_path,
    macos_replace_staged_with_rollback, macos_stage_verified_replacement_with,
    macos_validate_archive_path, MACOS_PRIVILEGED_REPLACEMENT_SHELL,
};

#[test]
fn privileged_archive_extraction_rejects_paths_and_links_outside_the_bundle() {
    use tar::EntryType;

    assert!(macos_validate_archive_path(
        Path::new("ShellX Drive Desktop.app/Contents/MacOS/drive"),
        EntryType::Regular,
        None,
    )
    .is_ok());
    assert!(macos_validate_archive_path(
        Path::new("ShellX Drive Desktop.app/Contents/Frameworks/Current"),
        EntryType::Symlink,
        Some(Path::new("Versions/Current")),
    )
    .is_ok());
    assert!(macos_validate_archive_path(
        Path::new("ShellX Drive Desktop.app/../outside"),
        EntryType::Regular,
        None,
    )
    .is_err());
    assert!(macos_validate_archive_path(
        Path::new("ShellX Drive Desktop.app/Contents/link"),
        EntryType::Symlink,
        Some(Path::new("../../outside")),
    )
    .is_err());
    assert!(macos_validate_archive_path(
        Path::new("ShellX Drive Desktop.app"),
        EntryType::Symlink,
        Some(Path::new("/private/tmp/outside")),
    )
    .is_err());
}

fn run_replacement(
    source: &Path,
    archive: &Path,
    staging: &Path,
    backup: &Path,
    digest: &str,
) -> std::process::ExitStatus {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(MACOS_PRIVILEGED_REPLACEMENT_SHELL)
        .arg("shellx-drive-updater")
        .arg(source)
        .arg(archive)
        .arg(staging)
        .arg(backup)
        .arg(digest)
        .status()
        .expect("run the unprivileged replacement script")
}

#[test]
fn privileged_replacement_rejects_relative_paths() {
    let relative = Path::new("ShellX Drive Desktop.app");
    let absolute = Path::new("/private/tmp/ShellX Drive Desktop.app");

    assert!(macos_privileged_replacement_arguments(
        relative,
        absolute,
        absolute,
        absolute,
        &"0".repeat(64)
    )
    .is_err());
}

#[test]
fn staging_copy_failure_leaves_the_current_app_untouched() {
    let root = tempfile::tempdir().expect("temporary root");
    let source = root.path().join("ShellX Drive Desktop.app");
    let incoming = root.path().join("incoming app");
    fs::create_dir(&source).expect("source bundle");
    fs::write(source.join("version"), "old").expect("source marker");

    assert!(
        macos_stage_verified_replacement_with(&source, &incoming, |_, staging| {
            fs::write(staging.join("partial-copy"), "partial")?;
            Err(std::io::Error::other("forced partial staging failure"))
        })
        .is_err()
    );
    assert_eq!(fs::read_to_string(source.join("version")).unwrap(), "old");
    assert!(fs::read_dir(root.path())
        .expect("temporary root entries")
        .all(|entry| !entry
            .expect("temporary root entry")
            .file_name()
            .to_string_lossy()
            .starts_with(".tauri-verified-app-")));
}

#[test]
fn unmoved_staged_replacement_is_cleaned_after_a_pre_move_error() {
    let root = tempfile::tempdir().expect("temporary root");
    let source = root.path().join("ShellX Drive Desktop.app");
    fs::create_dir(&source).expect("source bundle");

    let staged = macos_stage_verified_replacement_with(&source, &source, |_, staging| {
        fs::write(staging.join("version"), "new")
    })
    .expect("staged replacement");
    let staged_path = staged.path().to_path_buf();
    assert!(staged_path.exists());

    drop(staged);

    assert!(!staged_path.exists());
}

#[test]
fn replacement_script_rejects_a_mutated_signed_archive_before_moving_the_app() {
    let root = tempfile::tempdir().expect("temporary root");
    let parent = root.path().join("Drive's \"quoted\" \\ folder\n雪");
    let source = parent.join("ShellX Drive Desktop.app");
    let archive = parent.join("signed archive.tar.gz");
    let staging = macos_privileged_staging_path(&source, root.path()).unwrap();
    let backup = parent.join(".backup");
    fs::create_dir_all(&source).expect("source bundle");
    fs::write(&archive, b"signed archive before mutation").expect("original archive");
    use sha2::{Digest, Sha256};
    let expected_digest = format!("{:x}", Sha256::digest(fs::read(&archive).unwrap()));
    fs::write(source.join("version"), "old").expect("source marker");
    fs::write(&archive, b"archive changed during authorization prompt").expect("mutated archive");

    assert!(!run_replacement(&source, &archive, &staging, &backup, &expected_digest).success());
    assert_eq!(fs::read_to_string(source.join("version")).unwrap(), "old");
    assert!(!staging.exists());
    assert!(!backup.exists());
}

#[test]
fn replacement_script_rejects_an_unsigned_archive_before_moving_the_app() {
    use sha2::{Digest, Sha256};

    let root = tempfile::tempdir().expect("temporary root");
    let source = root.path().join("ShellX Drive Desktop.app");
    let incoming = root.path().join("Next.app");
    let archive = root.path().join("update.tar.gz");
    let staging = macos_privileged_staging_path(&source, root.path()).unwrap();
    let backup = root.path().join(".backup");
    fs::create_dir(&source).expect("source bundle");
    fs::create_dir(&incoming).expect("incoming bundle");
    fs::write(source.join("version"), "old").expect("source marker");
    fs::write(incoming.join("version"), "unsigned").expect("incoming marker");
    assert!(Command::new("/usr/bin/tar")
        .args(["-czf"])
        .arg(&archive)
        .arg("-C")
        .arg(root.path())
        .arg("Next.app")
        .status()
        .unwrap()
        .success());
    let digest = format!("{:x}", Sha256::digest(fs::read(&archive).unwrap()));

    assert!(!run_replacement(&source, &archive, &staging, &backup, &digest).success());
    assert_eq!(fs::read_to_string(source.join("version")).unwrap(), "old");
    assert!(!staging.exists());
    assert!(!backup.exists());
}

#[test]
fn replacement_script_staging_failure_leaves_current_bundle_in_place() {
    let root = tempfile::tempdir().expect("temporary root");
    let source = root.path().join("ShellX Drive Desktop.app");
    let missing_archive = root.path().join("missing replacement.tar.gz");
    let staging = macos_privileged_staging_path(&source, root.path()).unwrap();
    let backup = root.path().join(".backup");
    fs::create_dir(&source).expect("source bundle");
    fs::write(source.join("version"), "old").expect("source marker");

    assert!(!run_replacement(
        &source,
        &missing_archive,
        &staging,
        &backup,
        &"0".repeat(64)
    )
    .success());
    assert_eq!(fs::read_to_string(source.join("version")).unwrap(), "old");
    assert!(!staging.exists());
    assert!(!backup.exists());
}

#[test]
fn destination_occupant_is_not_replaced_or_removed() {
    let root = tempfile::tempdir().expect("temporary root");
    let source = root.path().join("ShellX Drive Desktop.app");
    let staged = root.path().join("staged app");
    let backup = root.path().join("backup/current_app");
    fs::create_dir(&source).expect("concurrent destination");
    fs::write(source.join("version"), "occupant").expect("occupant marker");
    fs::create_dir_all(&staged).expect("staged replacement");
    fs::write(staged.join("version"), "new").expect("staged marker");
    fs::create_dir_all(&backup).expect("backup bundle");
    fs::write(backup.join("version"), "old").expect("backup marker");

    assert!(macos_replace_staged_with_rollback(&staged, &source, &backup).is_err());
    assert_eq!(
        fs::read_to_string(source.join("version")).unwrap(),
        "occupant"
    );
    assert_eq!(fs::read_to_string(staged.join("version")).unwrap(), "new");
    assert_eq!(fs::read_to_string(backup.join("version")).unwrap(), "old");
}

#[test]
fn unprivileged_replacement_restores_the_current_bundle_when_the_new_move_fails() {
    let root = tempfile::tempdir().expect("temporary root");
    let source = root.path().join("ShellX Drive Desktop.app");
    let staged = root.path().join("missing replacement.app");
    let backup = root.path().join("backup/current_app");
    fs::create_dir_all(&backup).expect("backup bundle");
    fs::write(backup.join("version"), "old").expect("backup marker");

    assert!(macos_replace_staged_with_rollback(&staged, &source, &backup).is_err());
    assert_eq!(fs::read_to_string(source.join("version")).unwrap(), "old");
    assert!(!backup.exists());
}

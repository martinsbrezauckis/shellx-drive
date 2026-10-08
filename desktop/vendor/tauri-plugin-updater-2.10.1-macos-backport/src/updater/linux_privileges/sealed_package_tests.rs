use super::SealedPackage;
use std::{fs, io, io::Write, process::Command};

#[test]
fn another_process_cannot_replace_the_verified_package() {
    let package = SealedPackage::new(b"verified package bytes").unwrap();
    let output = Command::new("/bin/sh")
        .args(["-c", "printf substituted > \"$1\"", "mutation-probe"])
        .arg(package.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(package.path()).unwrap(), b"verified package bytes");
}

#[test]
fn reopened_file_cannot_write_grow_or_shrink() {
    let package = SealedPackage::new(b"verified package bytes").unwrap();
    let mut reopened = fs::OpenOptions::new()
        .write(true)
        .open(package.path())
        .unwrap();
    for result in [
        reopened.write_all(b"other"),
        reopened.set_len(0),
        reopened.set_len(1000),
    ] {
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
    }
    assert_eq!(fs::read(package.path()).unwrap(), b"verified package bytes");
}

#[test]
fn child_reads_original_bytes_without_inheriting_the_descriptor() {
    let package = SealedPackage::new(b"verified package bytes").unwrap();
    let output = Command::new("/bin/cat")
        .arg(package.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"verified package bytes");
    let path = package.path().to_owned();
    drop(package);
    assert!(fs::read(path).is_err());
}

#[test]
fn same_uid_pre_seal_replacement_is_rejected() {
    let result = SealedPackage::new_with_test_pre_seal_hook(b"verified package bytes", |path| {
        run_same_uid_mutation(path, "printf 'tampered package bytes' > \"$1\"")
    });

    let error = match result {
        Ok(_) => panic!("pre-seal replacement must not produce a package"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn same_uid_pre_seal_truncation_is_rejected() {
    let result = SealedPackage::new_with_test_pre_seal_hook(b"verified package bytes", |path| {
        run_same_uid_mutation(path, ": > \"$1\"")
    });

    let error = match result {
        Ok(_) => panic!("pre-seal truncation must not produce a package"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

fn run_same_uid_mutation(path: &std::path::Path, script: &str) -> io::Result<()> {
    let status = Command::new("/bin/sh")
        .args(["-c", script, "mutation-probe"])
        .arg(path)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("same-UID mutation fixture did not run"))
    }
}

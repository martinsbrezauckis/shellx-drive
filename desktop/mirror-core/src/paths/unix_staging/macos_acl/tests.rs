use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
};

use super::super::{macos_directory, validate_private_directory, validate_private_file};
use super::*;
use crate::{download_staging_root, initialize_owned_staging_root};

const ACL_READ_DATA: libc::c_int = 1 << 1;
const ACL_WRITE_DATA: libc::c_int = 1 << 2;
const ACL_EXECUTE: libc::c_int = 1 << 3;
const ACL_DELETE: libc::c_int = 1 << 4;
const ACL_ENTRY_INHERITED: libc::c_int = 1 << 4;
const ACL_ENTRY_FILE_INHERIT: libc::c_int = 1 << 5;
const ACL_ENTRY_DIRECTORY_INHERIT: libc::c_int = 1 << 6;

unsafe extern "C" {
    fn acl_create_entry(acl: *mut *mut c_void, entry: *mut AclEntry) -> libc::c_int;
    fn acl_set_tag_type(entry: AclEntry, tag: libc::c_int) -> libc::c_int;
    fn acl_set_qualifier(entry: AclEntry, principal: *const c_void) -> libc::c_int;
    fn acl_get_permset(entry: AclEntry, permissions: *mut *mut c_void) -> libc::c_int;
    fn acl_clear_perms(permissions: *mut c_void) -> libc::c_int;
    fn acl_add_perm(permissions: *mut c_void, permission: libc::c_int) -> libc::c_int;
    fn acl_get_perm_np(permissions: *mut c_void, permission: libc::c_int) -> libc::c_int;
    fn acl_get_flagset_np(object: *mut c_void, flags: *mut *mut c_void) -> libc::c_int;
    fn acl_add_flag_np(flags: *mut c_void, flag: libc::c_int) -> libc::c_int;
    fn acl_get_flag_np(flags: *mut c_void, flag: libc::c_int) -> libc::c_int;
}

fn foreign_uid() -> libc::uid_t {
    // membership.h permits synthesized UUIDs for unknown UIDs. No account or
    // other-user session is created; the foreign qualifier is read back exactly.
    (unsafe { libc::geteuid() }) ^ 0x8000_0000
}

fn install(file: &File, uid: libc::uid_t, tag: libc::c_int, inherit: bool) {
    let mut acl = Acl(unsafe { acl_init(1) });
    assert!(!acl.0.is_null());
    let mut entry = null_mut();
    assert_eq!(unsafe { acl_create_entry(&mut acl.0, &mut entry) }, 0);
    assert_eq!(unsafe { acl_set_tag_type(entry, tag) }, 0);
    let mut principal = [0_u8; 16];
    assert_eq!(unsafe { mbr_uid_to_uuid(uid, principal.as_mut_ptr()) }, 0);
    assert_eq!(
        unsafe { acl_set_qualifier(entry, principal.as_ptr().cast()) },
        0
    );
    let mut permissions = null_mut();
    assert_eq!(unsafe { acl_get_permset(entry, &mut permissions) }, 0);
    assert_eq!(unsafe { acl_clear_perms(permissions) }, 0);
    for permission in if tag == ACL_EXTENDED_DENY {
        vec![ACL_DELETE]
    } else {
        vec![ACL_READ_DATA, ACL_WRITE_DATA, ACL_EXECUTE]
    } {
        assert_eq!(unsafe { acl_add_perm(permissions, permission) }, 0);
    }
    if inherit {
        let mut flags = null_mut();
        assert_eq!(unsafe { acl_get_flagset_np(entry, &mut flags) }, 0);
        for flag in [ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT] {
            assert_eq!(unsafe { acl_add_flag_np(flags, flag) }, 0);
        }
    }
    assert_eq!(
        unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) },
        0
    );
}

fn assert_entries(file: &File, expected: usize, inherited: bool) {
    let acl = Acl::read(file).unwrap();
    let mut count = 0;
    if let Some(acl) = acl {
        acl.entries(|entry| {
            count += 1;
            if inherited {
                let mut tag = 0;
                assert_eq!(unsafe { acl_get_tag_type(entry, &mut tag) }, 0);
                assert_eq!(tag, ACL_EXTENDED_ALLOW);
                let mut flags = null_mut();
                assert_eq!(unsafe { acl_get_flagset_np(entry, &mut flags) }, 0);
                assert_eq!(unsafe { acl_get_flag_np(flags, ACL_ENTRY_INHERITED) }, 1);
                let mut permissions = null_mut();
                assert_eq!(unsafe { acl_get_permset(entry, &mut permissions) }, 0);
                for permission in [ACL_READ_DATA, ACL_WRITE_DATA] {
                    assert_eq!(unsafe { acl_get_perm_np(permissions, permission) }, 1);
                }
                let qualifier = unsafe { acl_get_qualifier(entry) };
                assert!(!qualifier.is_null());
                let principal = unsafe { qualifier.cast::<[u8; 16]>().read_unaligned() };
                unsafe { acl_free(qualifier) };
                let mut foreign = [0_u8; 16];
                assert_eq!(
                    unsafe { mbr_uid_to_uuid(foreign_uid(), foreign.as_mut_ptr()) },
                    0
                );
                assert_eq!(principal, foreign);
            }
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(count, expected);
}

fn empty_file(path: &std::path::Path) -> File {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap()
}

#[test]
fn inherited_foreign_acl_is_cleared_before_new_staging_holds_bytes() {
    let parent = tempfile::tempdir().unwrap();
    let parent_fd = macos_directory::open_directory(parent.path()).unwrap();
    install(&parent_fd, foreign_uid(), ACL_EXTENDED_ALLOW, true);

    let control = parent.path().join("unprotected-control");
    fs::DirBuilder::new().mode(0o700).create(&control).unwrap();
    let control_fd = macos_directory::open_directory(&control).unwrap();
    assert_entries(&control_fd, 1, true);
    assert!(validate_private_directory(&control).is_err());

    let pair = parent.path().join("Drive");
    fs::create_dir(&pair).unwrap();
    let root = download_staging_root(&pair).unwrap();
    let owned = initialize_owned_staging_root(&pair, &root, "download").unwrap();
    let batch = owned.create_batch(7).unwrap();
    for path in [&root, &batch] {
        let fd = macos_directory::open_directory(path).unwrap();
        assert_entries(&fd, 0, false);
        assert_eq!(fd.metadata().unwrap().mode() & 0o777, 0o700);
        validate_private_directory(path).unwrap();
    }
    // Demonstrate file inheritance directly, then protect the original empty FD.
    let mut file = empty_file(&parent.path().join("inherited-payload"));
    assert_entries(&file, 1, true);
    assert!(validate_private_file(&file).is_err());
    let before = file.metadata().unwrap();
    protect_new_private_file(&file).unwrap();
    assert_entries(&file, 0, false);
    let after = file.metadata().unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.uid(),
            before.nlink()
        ),
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.uid(),
            after.nlink()
        )
    );
    file.write_all(b"private fixture bytes").unwrap();
    validate_private_file(&file).unwrap();
    assert_entries(&parent_fd, 1, false);
    assert_entries(&control_fd, 1, true);
}

#[test]
fn existing_foreign_acl_and_terminal_payload_acl_fail_closed_without_repair() {
    let parent = tempfile::tempdir().unwrap();
    let pair = parent.path().join("Drive");
    fs::create_dir(&pair).unwrap();
    let root = download_staging_root(&pair).unwrap();
    let owned = initialize_owned_staging_root(&pair, &root, "download").unwrap();
    let batch = owned.create_batch(9).unwrap();
    let payload = batch.join("payload");
    let mut file = empty_file(&payload);
    protect_new_private_file(&file).unwrap();
    file.write_all(b"already-private data").unwrap();
    owned.validate_for_publication(&batch).unwrap();
    install(&file, foreign_uid(), ACL_EXTENDED_ALLOW, false);
    assert!(validate_private_file(&file).is_err());
    // Root/batch privacy protects retained user trees without editing or
    // rejecting their child ACLs. Actual payload consumers validate the FD.
    owned.validate_for_publication(&batch).unwrap();
    let reopened = crate::paths::open_local_regular_file(&payload).unwrap();
    assert!(validate_private_file(&reopened).is_err());
    assert!(protect_new_private_file(&file).is_err());
    assert_entries(&file, 1, false);
    assert_eq!(fs::read(&payload).unwrap(), b"already-private data");
    let batch_fd = macos_directory::open_directory(&batch).unwrap();
    install(&batch_fd, foreign_uid(), ACL_EXTENDED_ALLOW, true);
    assert!(crate::ensure_private_staging_directory(&batch).is_err());
    assert_entries(&batch_fd, 1, false);
}

#[test]
fn absent_acl_owner_allow_and_deny_delete_are_admitted_without_changes() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("private");
    super::super::create_private_directory(&path).unwrap();
    let directory = macos_directory::open_directory(&path).unwrap();
    let file = empty_file(&path.join("payload"));
    assert_entries(&directory, 0, false);
    assert_entries(&file, 0, false);
    validate_private_directory(&path).unwrap();
    validate_private_file(&file).unwrap();
    for (uid, tag) in [
        (foreign_uid(), ACL_EXTENDED_DENY),
        (unsafe { libc::geteuid() }, ACL_EXTENDED_ALLOW),
    ] {
        install(&directory, uid, tag, false);
        install(&file, uid, tag, false);
        validate_private_directory(&path).unwrap();
        validate_private_file(&file).unwrap();
        assert_entries(&directory, 1, false);
        assert_entries(&file, 1, false);
    }
}

#[test]
fn private_creation_preserves_no_follow_and_rejects_unsafe_scrub_targets() {
    let parent = tempfile::tempdir().unwrap();
    let real = parent.path().join("real");
    super::super::create_private_directory(&real).unwrap();
    let link = parent.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(validate_private_directory(&link).is_err());
    assert!(super::super::create_private_directory(&link.join("child")).is_err());
    assert!(!real.join("child").exists());
    let file = empty_file(&real.join("payload"));
    install(&file, foreign_uid(), ACL_EXTENDED_ALLOW, false);
    let file_link = real.join("payload-link");
    std::os::unix::fs::symlink(real.join("payload"), &file_link).unwrap();
    assert!(fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&file_link)
        .is_err());
    assert_entries(&file, 1, false);
    fs::hard_link(real.join("payload"), real.join("alias")).unwrap();
    assert!(protect_new_private_file(&file).is_err());
    assert_entries(&file, 1, false);
    let broad = empty_file(&real.join("broad"));
    broad
        .set_permissions(fs::Permissions::from_mode(0o644))
        .unwrap();
    install(&broad, foreign_uid(), ACL_EXTENDED_ALLOW, false);
    assert!(protect_new_private_file(&broad).is_err());
    assert_entries(&broad, 1, false);
    let directory = macos_directory::open_directory(&real).unwrap();
    assert!(protect_new_private_file(&directory).is_err());
}

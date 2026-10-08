//! Darwin extended ACLs are independent of the owner-private POSIX mode.

use std::{ffi::c_void, fs::File, os::fd::AsRawFd, ptr::null_mut};

use crate::{DesktopError, Result};

// ABI verified against the installed SDK's sys/acl.h and membership.h;
// these opaque pointers, enum values and symbols are exported by libSystem.
type AclEntry = *mut c_void;
const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
const ACL_EXTENDED_ALLOW: libc::c_int = 1;
const ACL_EXTENDED_DENY: libc::c_int = 2;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const ACL_NEXT_ENTRY: libc::c_int = -1;

unsafe extern "C" {
    fn acl_init(count: libc::c_int) -> *mut c_void;
    fn acl_free(object: *mut c_void) -> libc::c_int;
    fn acl_valid(acl: *mut c_void) -> libc::c_int;
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: libc::c_int, acl: *mut c_void, kind: libc::c_int) -> libc::c_int;
    fn acl_get_entry(acl: *mut c_void, index: libc::c_int, entry: *mut AclEntry) -> libc::c_int;
    fn acl_get_tag_type(entry: AclEntry, tag: *mut libc::c_int) -> libc::c_int;
    fn acl_get_qualifier(entry: AclEntry) -> *mut c_void;
    fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> libc::c_int;
}

struct Acl(*mut c_void);

impl Drop for Acl {
    fn drop(&mut self) {
        unsafe { acl_free(self.0) };
    }
}

impl Acl {
    fn read(file: &File) -> Result<Option<Self>> {
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let error = std::io::Error::last_os_error();
            // Darwin's filesec_get_property reports ENOENT for an absent ACL
            // on an existing FD. Unsupported or unreadable ACLs fail closed.
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(DesktopError::Io(error));
        }
        let acl = Self(acl);
        if unsafe { acl_valid(acl.0) } != 0 {
            return Err(DesktopError::Io(std::io::Error::last_os_error()));
        }
        Ok(Some(acl))
    }

    fn entries(&self, mut check: impl FnMut(AclEntry) -> Result<()>) -> Result<()> {
        let mut index = ACL_FIRST_ENTRY;
        loop {
            let mut entry = null_mut();
            if unsafe { acl_get_entry(self.0, index, &mut entry) } != 0 {
                let error = std::io::Error::last_os_error();
                // Darwin returns 0 for a found entry, -1/EINVAL at the end.
                // The snapshot is valid, immutable and uses only legal indices.
                if error.raw_os_error() == Some(libc::EINVAL) {
                    return Ok(());
                }
                return Err(DesktopError::Io(error));
            }
            if entry.is_null() {
                return Err(DesktopError::UnsafePath(
                    "Darwin returned an empty ACL entry".into(),
                ));
            }
            check(entry)?;
            index = ACL_NEXT_ENTRY;
        }
    }
}

pub(super) fn validate(file: &File) -> Result<()> {
    let Some(acl) = Acl::read(file)? else {
        return Ok(());
    };
    acl.entries(|entry| {
        let mut tag = 0;
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
            return Err(DesktopError::Io(std::io::Error::last_os_error()));
        }
        if tag == ACL_EXTENDED_DENY {
            return Ok(());
        }
        if tag != ACL_EXTENDED_ALLOW {
            return Err(DesktopError::UnsafePath(
                "private staging has an unknown ACL entry".into(),
            ));
        }
        let mut owner = [0_u8; 16];
        let error = unsafe { mbr_uid_to_uuid(libc::geteuid(), owner.as_mut_ptr()) };
        if error != 0 {
            return Err(DesktopError::Io(std::io::Error::from_raw_os_error(error)));
        }
        let qualifier = unsafe { acl_get_qualifier(entry) };
        if qualifier.is_null() {
            return Err(DesktopError::Io(std::io::Error::last_os_error()));
        }
        let principal = unsafe { qualifier.cast::<[u8; 16]>().read_unaligned() };
        unsafe { acl_free(qualifier) };
        if principal != owner {
            return Err(DesktopError::UnsafePath(
                "private staging ACL grants another principal access".into(),
            ));
        }
        Ok(())
    })
}

/// Called only after admitting a newly created, empty, owner-private object.
pub(super) fn clear(file: &File) -> Result<()> {
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let acl = Acl(acl);
    if unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) } != 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    if let Some(readback) = Acl::read(file)? {
        readback.entries(|_| {
            Err(DesktopError::UnsafePath(
                "new private staging retained an ACL entry".into(),
            ))
        })?;
    }
    Ok(())
}

pub(in crate::paths) fn protect_new_private_file(file: &File) -> Result<()> {
    use std::{os::unix::fs::MetadataExt, path::Path};
    let before = file.metadata()?;
    super::validate_owner_private(&before, Path::new("new private staging file"), false)?;
    if before.len() != 0 || before.nlink() != 1 {
        return Err(DesktopError::UnsafePath(
            "new private staging file is not empty and single-linked".into(),
        ));
    }
    clear(file)?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.nlink() != after.nlink()
        || after.len() != 0
    {
        return Err(DesktopError::UnsafePath(
            "new private staging file changed during protection".into(),
        ));
    }
    super::validate_private_file(file)
}

#[cfg(test)]
mod tests;

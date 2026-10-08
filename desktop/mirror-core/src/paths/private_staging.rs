//! Windows-only staging ownership boundary.
//!
//! Pair-bound markers constrain cleanup scope but are intentionally not a
//! secret.  This module supplies the separate access-control proof required
//! before private staging may hold mirrored bytes.

use std::{
    ffi::c_void,
    fs,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::Path,
    ptr::{null, null_mut},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, GENERIC_ALL, HANDLE},
    Security::Authorization::{
        GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
        NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    },
    Security::{
        EqualSid, GetAce, GetSecurityDescriptorControl, GetTokenInformation,
        InitializeSecurityDescriptor, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
        SetSecurityDescriptorOwner, TokenUser, ACCESS_ALLOWED_ACE, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SE_DACL_PRESENT,
        SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    },
    System::SystemServices::ACCESS_ALLOWED_ACE_TYPE,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

use crate::{DesktopError, Result};

const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const INHERIT_TO_CHILDREN: u32 = 3;

#[repr(C)]
#[derive(Default)]
struct SecurityDescriptor {
    revision: u8,
    sbz1: u8,
    control: u16,
    owner: *mut c_void,
    group: *mut c_void,
    sacl: *mut c_void,
    dacl: *mut c_void,
}

struct CurrentUserSid {
    _storage: Vec<u8>,
    sid: *mut c_void,
}

struct PrivateAcl {
    sid: CurrentUserSid,
    acl: *mut c_void,
}

impl Drop for PrivateAcl {
    fn drop(&mut self) {
        if !self.acl.is_null() {
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.acl) };
        }
    }
}

fn current_user_sid() -> Result<CurrentUserSid> {
    let mut token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let mut required = 0_u32;
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required) };
    if required == 0 {
        unsafe { CloseHandle(token) };
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let mut storage = vec![0_u8; required as usize];
    let success = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    };
    unsafe { CloseHandle(token) };
    if success == 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let sid = unsafe {
        (storage.as_ptr().cast::<TOKEN_USER>())
            .read_unaligned()
            .User
            .Sid
    };
    if sid.is_null() {
        return Err(DesktopError::InvalidState(
            "Windows returned an empty current-user SID".to_string(),
        ));
    }
    Ok(CurrentUserSid {
        _storage: storage,
        sid,
    })
}

fn private_acl(inheritance: u32) -> Result<PrivateAcl> {
    let sid = current_user_sid()?;
    let trustee = TRUSTEE_W {
        pMultipleTrustee: null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_USER,
        ptstrName: sid.sid.cast(),
    };
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: inheritance,
        Trustee: trustee,
    };
    let mut acl = null_mut();
    let error = unsafe { SetEntriesInAclW(1, &access, null(), &mut acl) };
    if error != 0 || acl.is_null() {
        return Err(DesktopError::Io(std::io::Error::from_raw_os_error(
            error as i32,
        )));
    }
    Ok(PrivateAcl {
        sid,
        acl: acl.cast(),
    })
}

fn private_security_attributes(
    acl: &PrivateAcl,
) -> Result<(SecurityDescriptor, SECURITY_ATTRIBUTES)> {
    let mut descriptor = SecurityDescriptor::default();
    if unsafe {
        InitializeSecurityDescriptor(
            (&mut descriptor as *mut SecurityDescriptor).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    if unsafe {
        SetSecurityDescriptorOwner(
            (&mut descriptor as *mut SecurityDescriptor).cast(),
            acl.sid.sid,
            0,
        )
    } == 0
        || unsafe {
            SetSecurityDescriptorDacl(
                (&mut descriptor as *mut SecurityDescriptor).cast(),
                1,
                acl.acl.cast(),
                0,
            )
        } == 0
        || unsafe {
            SetSecurityDescriptorControl(
                (&mut descriptor as *mut SecurityDescriptor).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        } == 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut descriptor as *mut SecurityDescriptor).cast(),
        bInheritHandle: 0,
    };
    Ok((descriptor, attributes))
}

fn path_wide(path: &Path) -> Result<Vec<u16>> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(DesktopError::UnsafePath(
            "private staging path contains a NUL".to_string(),
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// Create a private staging directory in one kernel operation.  Existing
/// paths are never adopted here; callers validate them independently.
pub(super) fn create_private_directory(path: &Path) -> Result<()> {
    let acl = private_acl(INHERIT_TO_CHILDREN)?;
    let (mut descriptor, mut attributes) = private_security_attributes(&acl)?;
    attributes.lpSecurityDescriptor = (&mut descriptor as *mut SecurityDescriptor).cast();
    let wide = path_wide(path)?;
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let error = unsafe { GetLastError() };
        return if error == ERROR_ALREADY_EXISTS {
            Err(DesktopError::Io(std::io::Error::from(
                std::io::ErrorKind::AlreadyExists,
            )))
        } else {
            Err(DesktopError::Io(std::io::Error::from_raw_os_error(
                error as i32,
            )))
        };
    }
    validate_private_directory(path)
}

fn checked_handle(path: &Path, directory: bool) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES);
    if directory {
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    } else {
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(DesktopError::UnsafePath(format!(
            "private staging object is not the expected non-reparse type: {}",
            path.display()
        )));
    }
    Ok(file)
}

fn validate_handle(file: &fs::File, expected_flags: u8) -> Result<()> {
    let current = current_user_sid()?;
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let error = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(DesktopError::Io(std::io::Error::from_raw_os_error(
            error as i32,
        )));
    }
    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
            }
        }
    }
    let _descriptor = Descriptor(descriptor);
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if descriptor.is_null()
        || dacl.is_null()
        || owner.is_null()
        || unsafe { EqualSid(owner, current.sid) } == 0
        || unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & (SE_DACL_PRESENT | SE_DACL_PROTECTED) != (SE_DACL_PRESENT | SE_DACL_PROTECTED)
    {
        return Err(DesktopError::UnsafePath(
            "private staging object is not owned by the current Windows user with a protected DACL"
                .to_string(),
        ));
    }
    // Windows maps GENERIC_ALL to FILE_ALL_ACCESS while applying some file
    // descriptors, so compare the single ACE structurally rather than by raw
    // bytes. Any second, inherited, foreign, or differently scoped ACE fails.
    let acl = unsafe { &*(dacl as *const windows_sys::Win32::Security::ACL) };
    let mut ace = null_mut();
    let got_ace = acl.AceCount == 1 && unsafe { GetAce(dacl.cast(), 0, &mut ace) } != 0;
    let valid_ace = if got_ace && !ace.is_null() {
        let allowed = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
        let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
        allowed.Header.AceType == ACCESS_ALLOWED_ACE_TYPE as u8
            && allowed.Header.AceFlags == expected_flags
            && (allowed.Mask == GENERIC_ALL || allowed.Mask == FILE_ALL_ACCESS)
            && unsafe { EqualSid(sid, current.sid) } != 0
    } else {
        false
    };
    if !valid_ace {
        return Err(DesktopError::UnsafePath(
            "private staging object has a foreign or permissive DACL".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_private_directory(path: &Path) -> Result<()> {
    validate_handle(
        &checked_handle(path, true)?,
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
    )
}

pub(super) fn protect_and_validate_file(file: &fs::File) -> Result<()> {
    // A file cannot have descendants, so its private ACE must not carry the
    // directory-only inheritance flags used by the surrounding staging tree.
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafePath(
            "private staging file is not a regular non-reparse file".to_string(),
        ));
    }
    let acl = private_acl(0)?;
    let error = unsafe {
        SetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            acl.sid.sid,
            null_mut(),
            acl.acl.cast(),
            null(),
        )
    };
    if error != 0 {
        return Err(DesktopError::Io(std::io::Error::from_raw_os_error(
            error as i32,
        )));
    }
    validate_handle(file, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_directory_round_trip_is_current_user_only() {
        let root = std::env::temp_dir().join(format!(
            "shellx-drive-private-staging-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        create_private_directory(&root).unwrap();
        validate_private_directory(&root).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inherited_directory_acl_is_not_accepted_as_private_staging() {
        let root = std::env::temp_dir().join(format!(
            "shellx-drive-private-staging-foreign-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        assert!(validate_private_directory(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

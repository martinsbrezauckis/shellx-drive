use std::{
    ffi::c_void,
    fs, io, iter,
    mem::size_of,
    os::windows::{fs::MetadataExt as _, fs::OpenOptionsExt as _, io::AsRawHandle as _},
    path::Path,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, GENERIC_READ, GENERIC_WRITE, HANDLE},
    Security::{
        AclSizeInformation,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetTokenInformation, IsWellKnownSid, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL,
        ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_DAC,
    },
    System::{
        SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

pub(super) fn configure_private_lock_options(options: &mut fs::OpenOptions, share_mode: u32) {
    options
        .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(super) fn set_private(path: &Path, expect_directory: bool) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.access_mode(READ_CONTROL | WRITE_DAC).custom_flags(
        FILE_FLAG_OPEN_REPARSE_POINT
            | if expect_directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            },
    );
    let file = options.open(path)?;
    apply_private_open_file(&file, expect_directory)
}

pub(super) fn apply_private_open_file(file: &fs::File, expect_directory: bool) -> io::Result<()> {
    validate_open_private_object(file, expect_directory)?;
    apply_and_verify_private_dacl(file.as_raw_handle() as HANDLE, expect_directory)
}

pub(super) fn verify_private_open_file(file: &fs::File, expect_directory: bool) -> io::Result<()> {
    validate_open_private_object(file, expect_directory)?;
    let (token, token_words) = current_token_user()?;
    let current_sid = unsafe { (*(token_words.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    verify_private_dacl(file.as_raw_handle() as HANDLE, current_sid)?;
    drop(token);
    Ok(())
}

fn validate_open_private_object(file: &fs::File, expect_directory: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.is_dir() != expect_directory
        || (!expect_directory && !metadata.is_file())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private data path must be the expected real file or directory",
        ));
    }
    Ok(())
}

fn apply_and_verify_private_dacl(handle: HANDLE, directory: bool) -> io::Result<()> {
    let (token, token_words) = current_token_user()?;
    let current_sid = unsafe { (*(token_words.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let current_sid_text = sid_string(current_sid)?;
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!(
        "D:P(A;{inheritance};FA;;;{current_sid_text})(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)"
    );
    set_dacl_from_sddl(handle, &sddl)?;
    verify_private_dacl(handle, current_sid)?;
    drop(token);
    Ok(())
}

fn set_dacl_from_sddl(handle: HANDLE, sddl: &str) -> io::Result<()> {
    let wide = sddl.encode_utf16().chain(iter::once(0)).collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(last_error("failed to build private Windows DACL"));
    }
    let descriptor_allocation = LocalAllocation(descriptor);
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return Err(last_error("failed to read generated private Windows DACL"));
    }
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    drop(descriptor_allocation);
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn grant_world_write_for_test(
    file: &fs::File,
    expect_directory: bool,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA;

    validate_open_private_object(file, expect_directory)?;
    let (token, token_words) = current_token_user()?;
    let current_sid = unsafe { (*(token_words.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let current_sid_text = sid_string(current_sid)?;
    let inheritance = if expect_directory { "OICI" } else { "" };
    let sddl = format!(
        "D:P(A;{inheritance};FA;;;{current_sid_text})(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)(A;{inheritance};0x{FILE_WRITE_DATA:x};;;WD)"
    );
    set_dacl_from_sddl(file.as_raw_handle() as HANDLE, &sddl)?;
    drop(token);
    Ok(())
}

fn current_token_user() -> io::Result<(OwnedHandle, Vec<usize>)> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error("failed to open the current Windows identity"));
    }
    let token = OwnedHandle(token);
    let mut required = 0u32;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required);
    }
    if required < size_of::<TOKEN_USER>() as u32 {
        return Err(last_error("failed to size the current Windows identity"));
    }
    let mut words = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            words.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(last_error("failed to read the current Windows identity"));
    }
    Ok((token, words))
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut raw = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 || raw.is_null() {
        return Err(last_error("failed to encode the current Windows identity"));
    }
    let allocation = LocalAllocation(raw.cast());
    let mut length = 0usize;
    while unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Windows SID was not UTF-16"))?;
    drop(allocation);
    Ok(text)
}

fn verify_private_dacl(handle: HANDLE, current_sid: PSID) -> io::Result<()> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() || owner.is_null() || dacl.is_null() {
        return Err(if status != 0 {
            io::Error::from_raw_os_error(status as i32)
        } else {
            last_error("failed to verify the private Windows DACL")
        });
    }
    let descriptor_allocation = LocalAllocation(descriptor);
    let owner_allowed = unsafe {
        EqualSid(owner, current_sid) != 0
            || IsWellKnownSid(owner, WinLocalSystemSid) != 0
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
    };
    if !owner_allowed {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private Windows object has an unexpected owner",
        ));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(last_error("private Windows DACL remains inheritable"));
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private Windows DACL remains inheritable",
        ));
    }
    let mut acl_info = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(last_error("failed to inspect private Windows DACL entries"));
    }
    let mut current_seen = false;
    for index in 0..acl_info.AceCount {
        let mut raw_ace: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(last_error("failed to inspect a private Windows DACL entry"));
        }
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        if unsafe { (*ace).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE as u8
            || unsafe { (*ace).Mask } & FILE_ALL_ACCESS != FILE_ALL_ACCESS
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private Windows DACL contains an unexpected access entry",
            ));
        }
        let sid = unsafe { ptr::addr_of_mut!((*ace).SidStart).cast::<c_void>() };
        let is_current = unsafe { EqualSid(sid, current_sid) != 0 };
        let allowed = is_current
            || unsafe { IsWellKnownSid(sid, WinLocalSystemSid) != 0 }
            || unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 };
        if !allowed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private Windows DACL grants access to an unexpected principal",
            ));
        }
        current_seen |= is_current;
    }
    drop(descriptor_allocation);
    if !current_seen {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private Windows DACL does not grant the service identity access",
        ));
    }
    Ok(())
}

fn last_error(context: &str) -> io::Error {
    let error = io::Error::last_os_error();
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::windows::{fs::OpenOptionsExt as _, io::AsRawHandle as _},
    };

    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_WRITE_DATA,
            READ_CONTROL, WRITE_DAC, WRITE_OWNER,
        },
    };

    use super::{
        apply_private_open_file, current_token_user, set_dacl_from_sddl, sid_string,
        verify_private_open_file, TOKEN_USER,
    };

    #[test]
    fn strict_private_dacl_rejects_every_foreign_write_capability() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("secret");
        fs::write(&path, b"secret").unwrap();
        let mut options = fs::OpenOptions::new();
        options
            .access_mode(READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(&path).unwrap();
        apply_private_open_file(&file, false).unwrap();
        verify_private_open_file(&file, false).unwrap();

        let (token, token_words) = current_token_user().unwrap();
        let current_sid = unsafe { (*(token_words.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        let current_sid_text = sid_string(current_sid).unwrap();
        for mask in [
            FILE_WRITE_DATA,
            FILE_GENERIC_WRITE,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            let sddl = format!(
                "D:P(A;;FA;;;{current_sid_text})(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{mask:x};;;WD)"
            );
            set_dacl_from_sddl(file.as_raw_handle() as HANDLE, &sddl).unwrap();
            assert!(
                verify_private_open_file(&file, false).is_err(),
                "foreign allow ACE mask 0x{mask:x} must be rejected"
            );
        }
        drop(token);
    }
}

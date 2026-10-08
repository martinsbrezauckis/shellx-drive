use std::{fs, io, mem, os::windows::io::AsRawHandle as _};

use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{LockFileEx, UnlockFile, LOCKFILE_EXCLUSIVE_LOCK},
    System::IO::OVERLAPPED,
};

const LOCK_RANGE_LOW: u32 = u32::MAX;
const LOCK_RANGE_HIGH: u32 = u32::MAX;

pub(super) fn lock(file: &fs::File, exclusive: bool) -> io::Result<()> {
    let flags = if exclusive {
        LOCKFILE_EXCLUSIVE_LOCK
    } else {
        0
    };
    let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
    let result = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            flags,
            0,
            LOCK_RANGE_LOW,
            LOCK_RANGE_HIGH,
            &mut overlapped,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn unlock(file: &fs::File) -> io::Result<()> {
    let result = unsafe {
        UnlockFile(
            file.as_raw_handle() as HANDLE,
            0,
            0,
            LOCK_RANGE_LOW,
            LOCK_RANGE_HIGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

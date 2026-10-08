//! Cross-process admission for state and Credential Manager mutations.

use std::{
    ffi::OsStr,
    fs, io,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    ptr,
};

use shellx_drive_desktop_core::{
    private_state_directory, validate_private_staging_file, Result as CoreResult,
};

use windows_sys::Win32::{
    Foundation::{ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_DAC, WRITE_OWNER},
    UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE},
};

const MAIN_WINDOW_TITLE: &str = "ShellX Drive Desktop";
const INSTANCE_LEASE_FILE: &str = "desktop-instance-v1.lock";

/// Holding this no-share handle serializes every state and credential mutation
/// across terminal sessions for the same Windows user. Its protected parent
/// prevents a different user from pre-creating this admission object.
pub(super) struct DesktopInstanceLease {
    _file: fs::File,
}

impl DesktopInstanceLease {
    /// `Ok(None)` means a same-user process in any Windows session owns the
    /// lease. Windows closes the held file handle if that process crashes.
    pub(super) fn acquire() -> CoreResult<Option<Self>> {
        let path = lease_file_path(&private_state_directory()?);
        let file = match open_no_share_lease(&path) {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = validate_private_staging_file(&file) {
            drop(file);
            return Err(error);
        }
        Ok(Some(Self { _file: file }))
    }
}

fn lease_file_path(private_state_directory: &Path) -> PathBuf {
    private_state_directory.join(INSTANCE_LEASE_FILE)
}

fn open_no_share_lease(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER)
        .create(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

pub(super) fn focus_existing_main_window() -> bool {
    let title = wide(MAIN_WINDOW_TITLE);
    let window = unsafe { FindWindowW(ptr::null(), title.as_ptr()) };
    if !window.is_null() {
        unsafe {
            ShowWindow(window, SW_RESTORE);
            SetForegroundWindow(window);
        }
        true
    } else {
        false
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_file_is_stably_namespaced_under_private_state() {
        assert_eq!(
            lease_file_path(Path::new("C:/private-state")),
            Path::new("C:/private-state").join(INSTANCE_LEASE_FILE)
        );
    }

    #[test]
    fn another_process_cannot_acquire_the_same_user_lease() {
        const CHILD: &str = "SHELLX_DRIVE_INSTANCE_LOCK_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(DesktopInstanceLease::acquire().unwrap().is_none());
            return;
        }
        let _lease = DesktopInstanceLease::acquire().unwrap().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::instance_lock::tests::another_process_cannot_acquire_the_same_user_lease",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child stdout: {}\nchild stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

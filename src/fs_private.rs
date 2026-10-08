use std::{fs, io, path::Path};

#[cfg(windows)]
mod windows;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub fn create_dir_all_private(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_dir_private(path)
}

pub fn set_dir_private(_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        windows::set_private(_path, true)?;
    }
    Ok(())
}

pub fn set_file_private(_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        windows::set_private(_path, false)?;
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn apply_private_dir_handle(file: &fs::File) -> io::Result<()> {
    windows::apply_private_open_file(file, true)
}

#[cfg(windows)]
pub(crate) fn apply_private_file_handle(file: &fs::File) -> io::Result<()> {
    windows::apply_private_open_file(file, false)
}

#[cfg(windows)]
pub(crate) fn configure_private_lock_options(options: &mut fs::OpenOptions, share_mode: u32) {
    windows::configure_private_lock_options(options, share_mode);
}

#[cfg(windows)]
pub(crate) fn verify_private_file_handle(file: &fs::File) -> io::Result<()> {
    windows::verify_private_open_file(file, false)
}

#[cfg(windows)]
pub(crate) fn verify_private_dir_handle(file: &fs::File) -> io::Result<()> {
    windows::verify_private_open_file(file, true)
}

#[cfg(all(windows, test))]
pub(crate) fn grant_world_write_for_test(
    file: &fs::File,
    expect_directory: bool,
) -> io::Result<()> {
    windows::grant_world_write_for_test(file, expect_directory)
}

pub fn set_process_private_umask() {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
}

pub fn write_file_private(path: &Path, content: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all_private(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write as _;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content)?;
        file.sync_all()?;
        set_file_private(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::Write as _;

        let mut file = fs::File::create(path)?;
        file.write_all(content)?;
        file.sync_all()?;
        set_file_private(path)
    }
}

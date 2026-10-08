use std::{fs::File, io, path::Path};

pub(super) struct InstanceLock {
    _file: File,
}

pub(super) fn acquire(data_dir: &Path) -> io::Result<InstanceLock> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = data_dir.join(".instance.lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(windows)]
    crate::fs_private::configure_private_lock_options(&mut options, 0);
    let file = options.open(&path)?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another ShellX Drive process already owns this data directory",
                ));
            }
            return Err(error);
        }
    }

    #[cfg(unix)]
    crate::fs_private::set_file_private(&path)?;
    #[cfg(windows)]
    crate::fs_private::apply_private_file_handle(&file)?;
    Ok(InstanceLock { _file: file })
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            let _ = unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

#[cfg(all(test, windows))]
#[path = "instance_lock/tests.rs"]
mod tests;

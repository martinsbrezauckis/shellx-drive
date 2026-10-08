// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Bind package-manager reads to the bytes verified by the updater.
//!
//! Filesystem access by the same UID must not permit replacement while an
//! authorization prompt is open. This does not protect a compromised updater
//! process (for example, arbitrary code execution or debugger control).

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::{Path, PathBuf},
};

pub(super) struct SealedPackage {
    _file: File,
    path: PathBuf,
}

#[cfg(test)]
type PreSealHook<'a> = &'a dyn Fn(&Path) -> io::Result<()>;

impl SealedPackage {
    #[cfg(test)]
    pub(super) fn new(bytes: &[u8]) -> io::Result<Self> {
        Self::new_inner(bytes, None)
    }

    #[cfg(not(test))]
    pub(super) fn new(bytes: &[u8]) -> io::Result<Self> {
        Self::new_inner(bytes)
    }

    #[cfg(test)]
    fn new_with_test_pre_seal_hook<F>(bytes: &[u8], hook: F) -> io::Result<Self>
    where
        F: Fn(&Path) -> io::Result<()>,
    {
        Self::new_inner(bytes, Some(&hook))
    }

    fn new_inner(
        bytes: &[u8],
        #[cfg(test)] pre_seal_hook: Option<PreSealHook<'_>>,
    ) -> io::Result<Self> {
        // No filesystem pathname or writable mapping is created. A same-UID
        // process can still reach this descriptor through procfs before
        // F_SEAL_WRITE, so compare the sealed object with the verified input.
        let fd = unsafe {
            libc::memfd_create(
                c"shellx-drive-update".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            file.as_raw_fd()
        ));
        file.write_all(bytes)?;
        #[cfg(test)]
        if let Some(hook) = pre_seal_hook {
            hook(&path)?;
        }
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let observed = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        if observed < 0 {
            return Err(io::Error::last_os_error());
        }
        if observed & seals != seals {
            return Err(io::Error::other("updater package sealing was incomplete"));
        }
        verify_sealed_bytes(&mut file, bytes)?;
        Ok(Self { _file: file, path })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

fn verify_sealed_bytes(file: &mut File, expected: &[u8]) -> io::Result<()> {
    let expected_len = u64::try_from(expected.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "updater package is too large"))?;
    if file.metadata()?.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sealed updater package length differs from verified bytes",
        ));
    }

    file.seek(SeekFrom::Start(0))?;
    let mut observed = [0_u8; 64 * 1024];
    for expected_chunk in expected.chunks(observed.len()) {
        let observed_chunk = &mut observed[..expected_chunk.len()];
        file.read_exact(observed_chunk)?;
        if observed_chunk != expected_chunk {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sealed updater package differs from verified bytes",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "sealed_package_tests.rs"]
mod tests;

//! Protected secret-file input shared by command-line binaries.
//!
//! Secret values never belong in argv. A file path may be passed in argv, but
//! the file itself must be a real regular file and private to its owner.

use std::{io::Read as _, path::Path};

use anyhow::{bail, Context};

const MAX_PRIVATE_SECRET_BYTES: u64 = 64 * 1024;

pub fn read_private_secret_file(path: &Path, label: &str) -> anyhow::Result<String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {label} file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open {label} file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} file must be a real regular file, not a link");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.mode() & 0o077 != 0 {
            bail!("{label} file must not grant group or other permissions");
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!("{label} file must be owned by the current user");
        }
    }
    #[cfg(windows)]
    crate::fs_private::verify_private_file_handle(&file).with_context(|| {
        format!(
            "{label} file {} does not have a protected private Windows DACL",
            path.display()
        )
    })?;

    if metadata.len() > MAX_PRIVATE_SECRET_BYTES {
        bail!("{label} file exceeds the private secret size limit");
    }

    let mut secret = String::new();
    (&mut file)
        .take(MAX_PRIVATE_SECRET_BYTES + 1)
        .read_to_string(&mut secret)
        .with_context(|| format!("failed to read {label} file {}", path.display()))?;
    if secret.len() as u64 > MAX_PRIVATE_SECRET_BYTES {
        bail!("{label} file exceeds the private secret size limit");
    }
    let secret = secret.trim_end_matches(['\r', '\n']).to_string();
    if secret.is_empty() {
        bail!("{label} file is empty");
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_private_regular_file_and_rejects_links() {
        let temp = tempfile::tempdir().unwrap();
        let secret_path = temp.path().join("secret");
        std::fs::write(&secret_path, "private-value\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            read_private_secret_file(&secret_path, "test").unwrap(),
            "private-value"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = temp.path().join("secret-link");
            symlink(&secret_path, &link).unwrap();
            assert!(read_private_secret_file(&link, "test").is_err());
        }
    }

    #[test]
    fn rejects_private_secret_files_above_the_size_limit() {
        let temp = tempfile::tempdir().unwrap();
        let secret_path = temp.path().join("oversized-secret");
        std::fs::write(
            &secret_path,
            vec![b'x'; (MAX_PRIVATE_SECRET_BYTES + 1) as usize],
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(read_private_secret_file(&secret_path, "test").is_err());
    }
}

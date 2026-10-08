//! Create private Unix app data and migrate only its held, owned physical leaf.

use std::{
    ffi::CString,
    fs,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::{Component, Path},
};

use crate::{DesktopError, Result};

#[cfg(target_os = "linux")]
const DIRECTORY_ACCESS: libc::c_int = libc::O_PATH;
#[cfg(target_os = "macos")]
const DIRECTORY_ACCESS: libc::c_int = libc::O_SEARCH;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const DIRECTORY_ACCESS: libc::c_int = libc::O_RDONLY;

struct Entry {
    parent: fs::File,
    name: CString,
    identity: libc::stat,
}

struct DirectoryChain {
    entries: Vec<Entry>,
    leaf: fs::File,
}

pub(super) fn initialize(path: &Path) -> Result<()> {
    protect_app_leaf(&open_chain(path)?)
}

fn open_chain(path: &Path) -> Result<DirectoryChain> {
    if !path.is_absolute() {
        return Err(unsafe_directory("application data path is not absolute"));
    }
    let mut parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(DIRECTORY_ACCESS | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open("/")?;
    let mut entries = Vec::new();
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => CString::new(name.as_bytes())
                .map_err(|_| unsafe_directory("application data component contains NUL"))?,
            _ => return Err(unsafe_directory("application data path is not normalized")),
        };
        let mut descriptor = open_at(&parent, &name);
        let mut created = false;
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error.into());
            }
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
                created = true;
            } else {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(error.into());
                }
            }
            descriptor = open_at(&parent, &name);
        }
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let child = unsafe { fs::File::from_raw_fd(descriptor) };
        entries.push(Entry {
            parent,
            name,
            identity: descriptor_metadata(&child)?,
        });
        if created {
            verify_identities(&entries)?;
            protect_owned_directory(&child)?;
            verify_identities(&entries)?;
        }
        parent = child;
    }
    if entries.is_empty() {
        return Err(unsafe_directory("application data path has no owned leaf"));
    }
    Ok(DirectoryChain {
        entries,
        leaf: parent,
    })
}

fn open_at(parent: &fs::File, name: &CString) -> libc::c_int {
    unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            DIRECTORY_ACCESS | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    }
}

fn protect_app_leaf(chain: &DirectoryChain) -> Result<()> {
    verify_identities(&chain.entries)?;
    protect_owned_directory(&chain.leaf)?;
    verify_identities(&chain.entries)
}

fn descriptor_metadata(file: &fs::File) -> Result<libc::stat> {
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut metadata) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(metadata)
}

fn verify_identities(entries: &[Entry]) -> Result<()> {
    for entry in entries {
        let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe {
            libc::fstatat(
                entry.parent.as_raw_fd(),
                entry.name.as_ptr(),
                &mut metadata,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
            || metadata.st_dev != entry.identity.st_dev
            || metadata.st_ino != entry.identity.st_ino
            || metadata.st_uid != entry.identity.st_uid
        {
            return Err(unsafe_directory(
                "application data directory identity changed",
            ));
        }
    }
    Ok(())
}

fn verify_owned_directory(metadata: &libc::stat) -> Result<()> {
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != unsafe { libc::geteuid() }
    {
        return Err(unsafe_directory(
            "application data leaf is not an owned directory",
        ));
    }
    Ok(())
}

fn protect_owned_directory(directory: &fs::File) -> Result<()> {
    let metadata = descriptor_metadata(directory)?;
    verify_owned_directory(&metadata)?;
    if metadata.st_mode & 0o7777 != 0o700
        && unsafe { libc::fchmodat(directory.as_raw_fd(), c".".as_ptr(), 0o700, 0) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let metadata = descriptor_metadata(directory)?;
    verify_owned_directory(&metadata)?;
    if metadata.st_mode & 0o7777 != 0o700 {
        return Err(unsafe_directory("application data leaf is not private"));
    }
    Ok(())
}

fn unsafe_directory(reason: &str) -> DesktopError {
    DesktopError::UnsafePath(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn root() -> (tempfile::TempDir, std::path::PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        (temporary, root)
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o7777
    }

    struct RestoreMode<'a>(&'a Path, u32);

    impl Drop for RestoreMode<'_> {
        fn drop(&mut self) {
            let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(self.1));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_default_state_and_registry_are_private_under_umask_0002() {
        const CHILD: &str = "SHELLX_DRIVE_APP_DATA_UMASK_TEST";
        if std::env::var_os(CHILD).is_none() {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "state::unix_app_data::tests::fresh_default_state_and_registry_are_private_under_umask_0002",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success());
            return;
        }
        // Only this isolated, single-test process changes its umask/environment.
        unsafe { libc::umask(0o002) };
        let (_temporary, root) = root();
        let data = root.join("missing-parent/share");
        std::env::set_var("XDG_DATA_HOME", &data);
        let state = crate::state::default_state_path().unwrap();
        assert_eq!(state, data.join("drivedesktop/state.json"));
        crate::state::private_state_directory().unwrap();
        assert!(crate::LinuxCredentialStore::service_account_keys()
            .unwrap()
            .is_empty());
        for path in [
            root.join("missing-parent"),
            data.clone(),
            data.join("drivedesktop"),
            data.join("drivedesktop/.shellx-drive-private"),
            data.join("drivedesktop/.shellx-drive-credential-registry-v1"),
        ] {
            assert_eq!(mode(&path), 0o700, "{}", path.display());
        }
    }

    #[test]
    fn legacy_leaf_migration_retains_inode_bytes_and_shared_ancestor_mode() {
        let (_temporary, root) = root();
        let shared = root.join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o775)).unwrap();
        for permissions in [0o775, 0o755] {
            let leaf = shared.join(format!("legacy-{permissions:o}"));
            fs::create_dir(&leaf).unwrap();
            fs::set_permissions(&leaf, fs::Permissions::from_mode(permissions)).unwrap();
            fs::write(leaf.join("state.json"), b"retained non-secret bytes").unwrap();
            let before = fs::metadata(&leaf).unwrap();
            initialize(&leaf).unwrap();
            initialize(&leaf).unwrap();
            let after = fs::metadata(&leaf).unwrap();
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(mode(&leaf), 0o700);
            assert_eq!(mode(&shared), 0o775);
            assert_eq!(
                fs::read(leaf.join("state.json")).unwrap(),
                b"retained non-secret bytes"
            );
        }
    }

    #[test]
    fn traverse_only_ancestor_retains_exact_mode_and_contained_bytes() {
        for permissions in [0o711, 0o111] {
            let (_temporary, root) = root();
            let shared = root.join("shared");
            let leaf = shared.join("drivedesktop");
            fs::create_dir_all(&leaf).unwrap();
            fs::set_permissions(&leaf, fs::Permissions::from_mode(0o775)).unwrap();
            fs::write(leaf.join("state.json"), b"retained non-secret bytes").unwrap();
            let before = fs::metadata(&leaf).unwrap();
            let _restore = RestoreMode(&shared, mode(&shared));
            fs::set_permissions(&shared, fs::Permissions::from_mode(permissions)).unwrap();
            initialize(&leaf).unwrap();
            let after = fs::metadata(&leaf).unwrap();
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(mode(&shared), permissions);
            assert_eq!(mode(&leaf), 0o700);
            assert_eq!(
                fs::read(leaf.join("state.json")).unwrap(),
                b"retained non-secret bytes"
            );
        }
    }

    #[test]
    fn symlink_leaf_and_ancestor_are_rejected_without_touching_target() {
        let (_temporary, root) = root();
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let link = root.join("link");
        symlink(&target, &link).unwrap();
        assert!(initialize(&link).is_err());
        assert!(initialize(&link.join("drivedesktop")).is_err());
        assert_eq!(mode(&target), 0o755);
        assert!(!target.join("drivedesktop").exists());
    }

    #[test]
    fn non_directory_leaf_is_rejected_and_its_bytes_retained() {
        let (_temporary, root) = root();
        let leaf = root.join("file");
        fs::write(&leaf, b"retain this file").unwrap();
        assert!(initialize(&leaf).is_err());
        assert_eq!(fs::read(&leaf).unwrap(), b"retain this file");
    }

    #[test]
    fn changed_leaf_identity_is_rejected_before_permission_migration() {
        let (_temporary, root) = root();
        let leaf = root.join("drivedesktop");
        fs::create_dir(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o775)).unwrap();
        let chain = open_chain(&leaf).unwrap();
        let retained = root.join("retained");
        fs::rename(&leaf, &retained).unwrap();
        fs::create_dir(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(protect_app_leaf(&chain).is_err());
        assert_eq!(mode(&leaf), 0o775);
        assert_eq!(mode(&retained), 0o775);
    }

    #[test]
    fn changed_ancestor_identity_is_rejected_before_permission_migration() {
        let (_temporary, root) = root();
        let shared = root.join("shared");
        let leaf = shared.join("drivedesktop");
        fs::create_dir_all(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o775)).unwrap();
        let chain = open_chain(&leaf).unwrap();
        let retained = root.join("retained");
        fs::rename(&shared, &retained).unwrap();
        fs::create_dir_all(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(protect_app_leaf(&chain).is_err());
        assert_eq!(mode(&leaf), 0o775);
        assert_eq!(mode(&retained.join("drivedesktop")), 0o775);
    }

    #[test]
    fn different_owner_metadata_is_rejected() {
        let (_temporary, root) = root();
        let directory = fs::File::open(&root).unwrap();
        let mut metadata = descriptor_metadata(&directory).unwrap();
        metadata.st_uid = unsafe { libc::geteuid() } ^ 1;
        assert!(verify_owned_directory(&metadata).is_err());
    }
}

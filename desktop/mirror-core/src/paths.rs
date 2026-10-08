use std::{
    ffi::OsStr,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{error::Result, hex_digest, DesktopError};

#[cfg(target_os = "windows")]
mod private_staging;
mod remote;
#[cfg(test)]
mod staging_tests;
#[cfg(unix)]
mod unix_staging;
pub use remote::{inspect_remote_paths, map_remote_paths, RemotePathIssue, RemotePathMapping};

/// Encode an admitted absolute path for a pathname-based Windows API without
/// depending on the process manifest or the host's long-path policy. This is
/// lexical conversion only: it does not follow links or replace caller pins.
#[cfg(target_os = "windows")]
pub fn windows_absolute_path_wide(path: &Path) -> Result<Vec<u16>> {
    use std::{os::windows::ffi::OsStrExt, path::Prefix};

    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(DesktopError::UnsafePath(
            "Windows API path must be absolute without parent traversal".to_string(),
        ));
    }
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(DesktopError::UnsafePath(
            "Windows API path contains a NUL".to_string(),
        ));
    }
    // Normalize ordinary Win32 separators and dot components before adding
    // the verbatim prefix, whose parser deliberately performs no expansion.
    let absolute = std::path::absolute(path)?;
    let wide = absolute.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut extended = match absolute.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_) => r"\\?\".encode_utf16().chain(wide).collect::<Vec<_>>(),
            Prefix::UNC(_, _) => r"\\?\UNC\"
                .encode_utf16()
                .chain(wide.into_iter().skip(2))
                .collect(),
            Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) | Prefix::Verbatim(_) => wide,
            _ => {
                return Err(DesktopError::UnsafePath(
                    "Windows API path uses an unsupported device namespace".to_string(),
                ));
            }
        },
        _ => {
            return Err(DesktopError::UnsafePath(
                "Windows API path has no absolute namespace".to_string(),
            ));
        }
    };
    extended.push(0);
    Ok(extended)
}

#[cfg(target_os = "windows")]
pub fn validate_private_staging_file(file: &fs::File) -> Result<()> {
    private_staging::protect_and_validate_file(file)
}

#[cfg(unix)]
pub fn validate_private_staging_file(file: &fs::File) -> Result<()> {
    unix_staging::validate_private_file(file)
}

/// Protect a create-new, empty staging payload inside an admitted private
/// directory before copying bytes. Existing bodies are only validated.
#[cfg(target_os = "macos")]
pub fn protect_new_private_staging_file(file: &fs::File) -> Result<()> {
    unix_staging::protect_new_private_file(file)
}

#[cfg(target_os = "windows")]
pub fn ensure_private_staging_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_not_link(path)?;
            if !metadata.is_dir() {
                return Err(DesktopError::UnsafePath(format!(
                    "private staging path is not a directory: {}",
                    path.display()
                )));
            }
            private_staging::validate_private_directory(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            private_staging::create_private_directory(path)
        }
        Err(error) => Err(DesktopError::Io(error)),
    }
}

#[cfg(unix)]
pub fn ensure_private_staging_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure_not_link(path)?;
            if !metadata.is_dir() {
                return Err(DesktopError::UnsafePath(format!(
                    "private staging path is not a directory: {}",
                    path.display()
                )));
            }
            unix_staging::validate_private_directory(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            unix_staging::create_private_directory(path)
        }
        Err(error) => Err(DesktopError::Io(error)),
    }
}

pub const PAIR_MARKER_FILE: &str = ".shellx-drive-pair.json";
const RESTORE_STAGING_DIR: &str = ".shellx-drive-restore-staging";
const DOWNLOAD_STAGING_DIR: &str = ".shellx-drive-download-staging";
const UPLOAD_STAGING_DIR: &str = ".shellx-drive-upload-staging";
const STAGING_ROOT_MARKER: &str = ".shellx-drive-staging-root-v1";
const STAGING_BATCH_MARKER: &str = ".shellx-drive-staging-batch-v1";
const STAGING_RETAINED_MARKER: &str = ".shellx-drive-staging-retained-v1";
const STAGING_SCHEMA: &str = "shellx-drive-desktop-staging-v1";
const STAGING_NAMESPACE_HEX_CHARS: usize = 32;
pub(super) const MAX_WINDOWS_PATH_CHARS: usize = 240;
pub(super) const MAX_WINDOWS_COMPONENT_CHARS: usize = 255;
pub(super) const MAX_PATH_DEPTH: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathIssue {
    pub path: PathBuf,
    pub reason: String,
}

/// A marker-bound, pair-specific sibling staging root. Markers are not a
/// secret; their purpose is to make the destructive cleanup scope explicit
/// and durable so arbitrary pre-existing sibling content is never adopted.
#[derive(Clone, Debug)]
pub struct OwnedStagingRoot {
    root: PathBuf,
    binding: String,
    batch_prefix: String,
}

/// A conservative path identity checkpoint for operations that await network
/// I/O. It is not a replacement for handle-relative Windows publication, but
/// it catches a replaced root/ancestor/target before a later mutation and lets
/// the caller fail closed into review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalOperationBoundary {
    root: PathBuf,
    target: PathBuf,
    existing: Vec<BoundaryEntry>,
    target_entry: Option<BoundaryEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundaryEntry {
    path: PathBuf,
    is_directory: bool,
    is_file: bool,
    length: u64,
    modified: Option<SystemTime>,
}

/// Requires the setup target to be a real, empty directory. The non-secret
/// marker is permitted only when recovering a previously-created pair.
pub fn ensure_empty_local_root(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() {
        return Err(DesktopError::UnsafePath(format!(
            "local root is not a directory: {}",
            root.display()
        )));
    }
    ensure_not_link(root)?;
    let entries = fs::read_dir(root)?;
    for entry in entries {
        let entry = entry?;
        if entry.file_name() != OsStr::new(PAIR_MARKER_FILE) {
            return Err(DesktopError::LocalFolderNotEmpty(root.to_path_buf()));
        }
    }
    Ok(())
}

/// A reviewed restore is prepared beside the paired root, never inside it.
/// A sibling directory keeps the staging move on the same ordinary volume and
/// prevents a failed multi-file download from appearing in the mirror.
pub fn restore_staging_root(local_root: &Path) -> Result<PathBuf> {
    sibling_private_root(local_root, RESTORE_STAGING_DIR, "restore staging")
}

/// Ordinary downloads use a distinct app-owned sibling staging root. Nothing
/// under the paired folder is ever treated as client scratch space.
pub fn download_staging_root(local_root: &Path) -> Result<PathBuf> {
    sibling_private_root(local_root, DOWNLOAD_STAGING_DIR, "download staging")
}

/// Uploads snapshot mutable local bodies in a separate sibling directory
/// before any network transfer. It is never part of the paired tree.
pub fn upload_staging_root(local_root: &Path) -> Result<PathBuf> {
    sibling_private_root(local_root, UPLOAD_STAGING_DIR, "upload staging")
}

fn sibling_private_root(local_root: &Path, name: &str, label: &str) -> Result<PathBuf> {
    let parent = local_root.parent().ok_or_else(|| {
        DesktopError::UnsafePath(format!("the selected local root has no parent for {label}"))
    })?;
    let binding = staging_pair_binding(local_root)?;
    let namespace = binding.get(..STAGING_NAMESPACE_HEX_CHARS).ok_or_else(|| {
        DesktopError::UnsafePath("private staging namespace is malformed".to_string())
    })?;
    let staging = parent.join(format!("{name}-{namespace}"));
    if staging.starts_with(local_root) {
        return Err(DesktopError::UnsafePath(format!(
            "{label} must stay outside the paired root"
        )));
    }
    Ok(staging)
}

/// Initialize or validate a staging root that belongs to this exact paired
/// directory. Existing unmarked, wrong-pair, linked, malformed, or unknown
/// sibling content is never repaired or deleted: the caller must surface a
/// review/error and leave it untouched.
pub fn initialize_owned_staging_root(
    local_root: &Path,
    staging_root: &Path,
    kind: &str,
) -> Result<OwnedStagingRoot> {
    if !matches!(kind, "upload" | "download" | "restore") {
        return Err(DesktopError::UnsafePath(
            "unknown private staging kind".to_string(),
        ));
    }
    let parent = local_root.parent().ok_or_else(|| {
        DesktopError::UnsafePath("the paired local root has no sibling staging parent".to_string())
    })?;
    if staging_root.parent() != Some(parent) || staging_root.starts_with(local_root) {
        return Err(DesktopError::UnsafePath(
            "private staging root is not a sibling of the paired root".to_string(),
        ));
    }
    ensure_not_link(local_root)?;
    let local_metadata = fs::symlink_metadata(local_root)?;
    if !local_metadata.is_dir() {
        return Err(DesktopError::UnsafePath(
            "paired local root is not a directory".to_string(),
        ));
    }
    ensure_not_link(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() {
        return Err(DesktopError::UnsafePath(
            "paired local root parent is not a directory".to_string(),
        ));
    }
    let binding = staging_pair_binding(local_root)?;
    let batch_prefix = format!("shellx-drive-{kind}-batch-v1-");
    let area = OwnedStagingRoot {
        root: staging_root.to_path_buf(),
        binding,
        batch_prefix,
    };

    #[cfg(target_os = "windows")]
    let _parent_pins = pin_windows_absolute_directory_chain(parent)?;
    match fs::symlink_metadata(staging_root) {
        Ok(metadata) => {
            ensure_not_link(staging_root)?;
            if !metadata.is_dir() {
                return Err(DesktopError::UnsafePath(format!(
                    "private staging root is not a directory: {}",
                    staging_root.display()
                )));
            }
            #[cfg(target_os = "windows")]
            private_staging::validate_private_directory(staging_root)?;
            area.validate_root()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Each admitted platform creates staging owner-private before any
            // mirrored body can enter it. Unknown platforms have no fallback.
            #[cfg(target_os = "windows")]
            private_staging::create_private_directory(staging_root)?;
            #[cfg(unix)]
            unix_staging::create_private_directory(staging_root)?;
            // Do not recursively remove a path whose post-create identity
            // could no longer be proven. A later run will fail closed.
            write_marker_new(&area.root_marker_path(), &area.root_marker())?;
            #[cfg(target_os = "windows")]
            private_staging::validate_private_directory(staging_root)?;
            #[cfg(unix)]
            unix_staging::validate_private_directory(staging_root)?;
            area.validate_root()?;
        }
        Err(error) => return Err(DesktopError::Io(error)),
    }
    Ok(area)
}

impl OwnedStagingRoot {
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Revalidate the ownership boundary immediately before a staged tree is
    /// published as a directory.  Callers that cannot retain every child file
    /// handle use this to fail closed if the trusted staging boundary changed.
    pub fn validate_for_publication(&self, batch: &Path) -> Result<()> {
        self.validate_root()?;
        self.validate_batch(batch)
    }

    /// Allocate a fresh owned batch and bind its create-new marker to this
    /// root/pair and exact strict batch identity before returning it.
    pub fn create_batch(&self, uniqueness: u64) -> Result<PathBuf> {
        #[cfg(target_os = "windows")]
        let _root_pins = pin_windows_absolute_directory_chain(&self.root)?;
        self.validate_root()?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                DesktopError::InvalidState("system clock predates Unix epoch".to_string())
            })?
            .as_micros();
        for retry in 0..8_u64 {
            let name = format!(
                "{}{stamp:020}-{uniqueness:020}-{retry:02}",
                self.batch_prefix
            );
            let batch = self.root.join(&name);
            #[cfg(target_os = "windows")]
            let created = private_staging::create_private_directory(&batch);
            #[cfg(unix)]
            let created = unix_staging::create_private_directory(&batch);
            match created {
                Ok(()) => {
                    // An incompletely initialized batch is deliberately not
                    // removed; future validation refuses it rather than
                    // guessing ownership.
                    write_marker_new(&batch.join(STAGING_BATCH_MARKER), &self.batch_marker(&name))?;
                    self.validate_batch(&batch)?;
                    return Ok(batch);
                }
                Err(DesktopError::Io(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(DesktopError::InvalidState(
            "could not allocate a unique owned staging batch".to_string(),
        ))
    }

    /// Delete only a currently valid marker-bound app batch. Every marker,
    /// root, batch, and descendant is revalidated immediately before the
    /// recursive deletion; any uncertainty leaves bytes untouched.
    pub fn remove_batch(&self, batch: &Path) -> Result<()> {
        #[cfg(target_os = "windows")]
        let _root_pins = pin_windows_absolute_directory_chain(&self.root)?;
        self.validate_root()?;
        self.validate_batch(batch)?;
        if self.is_retained_batch(batch)? {
            return Err(DesktopError::InvalidState(
                "a retained staging batch contains local recovery bytes and must not be deleted"
                    .to_string(),
            ));
        }
        self.validate_root()?;
        self.validate_batch(batch)?;
        fs::remove_dir_all(batch)?;
        Ok(())
    }

    /// Preserve a failed native-replacement backup only after all ordinary
    /// recovery publications failed. This marker makes aged cleanup skip the
    /// batch; the caller must surface its exact recovery path in NeedsReview.
    /// It is deliberately one batch per blocked run, never a normal-sync
    /// backup mechanism.
    pub fn retain_batch(&self, batch: &Path) -> Result<()> {
        self.validate_root()?;
        self.validate_batch(batch)?;
        write_marker_new(
            &self.retained_marker_path(batch),
            &self.retained_marker(batch)?,
        )?;
        self.validate_batch(batch)?;
        if !self.is_retained_batch(batch)? {
            return Err(DesktopError::InvalidState(
                "retained staging marker could not be verified".to_string(),
            ));
        }
        Ok(())
    }

    /// Remove only aged, strictly valid owned batches. Unknown or spoofed
    /// direct children make the entire root fail closed before any deletion.
    pub fn cleanup_aged_batches(&self, age: Duration) -> Result<usize> {
        let batches = self.valid_batches()?;
        let now = SystemTime::now();
        let mut removed = 0;
        for batch in batches {
            if self.is_retained_batch(&batch)? {
                continue;
            }
            let metadata = fs::symlink_metadata(&batch)?;
            let old_enough = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|elapsed| elapsed >= age);
            if old_enough {
                self.remove_batch(&batch)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn root_marker_path(&self) -> PathBuf {
        self.root.join(STAGING_ROOT_MARKER)
    }

    fn root_marker(&self) -> String {
        format!("{STAGING_SCHEMA}\nroot\n{}\n", self.binding)
    }

    fn batch_marker(&self, batch_name: &str) -> String {
        format!("{STAGING_SCHEMA}\nbatch\n{}\n{batch_name}\n", self.binding)
    }

    fn retained_marker_path(&self, batch: &Path) -> PathBuf {
        batch.join(STAGING_RETAINED_MARKER)
    }

    fn retained_marker(&self, batch: &Path) -> Result<String> {
        let name = batch
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                DesktopError::UnsafePath("retained staging batch has no Unicode name".to_string())
            })?;
        Ok(format!(
            "{STAGING_SCHEMA}\nretained\n{}\n{name}\n",
            self.binding
        ))
    }

    fn is_retained_batch(&self, batch: &Path) -> Result<bool> {
        let marker = self.retained_marker_path(batch);
        match fs::symlink_metadata(&marker) {
            Ok(_) => {
                validate_regular_marker(&marker, &self.retained_marker(batch)?)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(DesktopError::Io(error)),
        }
    }

    fn validate_root(&self) -> Result<()> {
        ensure_not_link(&self.root)?;
        let metadata = fs::symlink_metadata(&self.root)?;
        if !metadata.is_dir() {
            return Err(DesktopError::UnsafePath(
                "private staging root is not a directory".to_string(),
            ));
        }
        #[cfg(target_os = "windows")]
        private_staging::validate_private_directory(&self.root)?;
        #[cfg(unix)]
        unix_staging::validate_private_directory(&self.root)?;
        validate_regular_marker(&self.root_marker_path(), &self.root_marker())?;
        self.valid_batches().map(|_| ())
    }

    fn valid_batches(&self) -> Result<Vec<PathBuf>> {
        ensure_not_link(&self.root)?;
        let mut batches = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            if name == OsStr::new(STAGING_ROOT_MARKER) {
                continue;
            }
            let name = name.to_str().ok_or_else(|| {
                DesktopError::UnsafePath("private staging child has a non-Unicode name".to_string())
            })?;
            if !self.is_strict_batch_name(name) {
                return Err(DesktopError::UnsafePath(format!(
                    "private staging root contains unowned content: {}",
                    entry.path().display()
                )));
            }
            self.validate_batch(&entry.path())?;
            batches.push(entry.path());
        }
        Ok(batches)
    }

    fn validate_batch(&self, batch: &Path) -> Result<()> {
        let parent = batch.parent().ok_or_else(|| {
            DesktopError::UnsafePath("owned staging batch has no parent".to_string())
        })?;
        if parent != self.root {
            return Err(DesktopError::UnsafePath(
                "owned staging batch escapes its staging root".to_string(),
            ));
        }
        ensure_not_link(batch)?;
        let metadata = fs::symlink_metadata(batch)?;
        if !metadata.is_dir() {
            return Err(DesktopError::UnsafePath(
                "owned staging batch is not a directory".to_string(),
            ));
        }
        #[cfg(target_os = "windows")]
        private_staging::validate_private_directory(batch)?;
        #[cfg(unix)]
        unix_staging::validate_private_directory(batch)?;
        let name = batch
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                DesktopError::UnsafePath("owned staging batch has a non-Unicode name".to_string())
            })?;
        if !self.is_strict_batch_name(name) {
            return Err(DesktopError::UnsafePath(
                "owned staging batch name is malformed".to_string(),
            ));
        }
        validate_regular_marker(&batch.join(STAGING_BATCH_MARKER), &self.batch_marker(name))?;
        ensure_tree_has_no_links(batch)?;
        Ok(())
    }

    fn is_strict_batch_name(&self, name: &str) -> bool {
        let Some(rest) = name.strip_prefix(&self.batch_prefix) else {
            return false;
        };
        let mut pieces = rest.split('-');
        matches!(
            (pieces.next(), pieces.next(), pieces.next(), pieces.next()),
            (Some(stamp), Some(unique), Some(retry), None)
                if stamp.len() == 20
                    && unique.len() == 20
                    && retry.len() == 2
                    && stamp.bytes().all(|byte| byte.is_ascii_digit())
                    && unique.bytes().all(|byte| byte.is_ascii_digit())
                    && retry.bytes().all(|byte| byte.is_ascii_digit())
        )
    }
}

/// Retain no-reparse handles for every absolute staging-root ancestor while a
/// Windows create or recursive cleanup resolves child paths. The final batch
/// is still validated separately and `remove_dir_all` does not traverse a
/// final reparse point; pinning the ancestry closes the redirectable interval.
#[cfg(target_os = "windows")]
fn pin_windows_absolute_directory_chain(path: &Path) -> Result<Vec<fs::File>> {
    use std::{
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::Component,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_TRAVERSE,
    };

    if !path.is_absolute() {
        return Err(DesktopError::UnsafePath(format!(
            "private staging root is not absolute: {}",
            path.display()
        )));
    }
    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    let mut saw_root = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => {
                current.push(component.as_os_str());
                saw_root = true;
            }
            Component::Normal(name) if saw_root => current.push(name),
            Component::Normal(_) | Component::CurDir | Component::ParentDir => {
                return Err(DesktopError::UnsafePath(format!(
                    "private staging root has an unsafe component: {}",
                    path.display()
                )));
            }
        }
        if saw_root {
            let handle = fs::OpenOptions::new()
                .read(true)
                .access_mode(FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&current)?;
            let metadata = handle.metadata()?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(DesktopError::UnsafeLink(current));
            }
            handles.push(handle);
        }
    }
    if handles.is_empty() {
        return Err(DesktopError::UnsafePath(
            "private staging root has no pinnable Windows ancestry".to_string(),
        ));
    }
    Ok(handles)
}

fn staging_pair_binding(local_root: &Path) -> Result<String> {
    ensure_not_link(local_root)?;
    let canonical = fs::canonicalize(local_root)?;
    ensure_not_link(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(STAGING_SCHEMA.as_bytes());
    hasher.update([0]);
    hasher.update(canonical.to_string_lossy().as_bytes());
    Ok(hex_digest(hasher.finalize().as_slice()))
}

fn write_marker_new(path: &Path, contents: &str) -> Result<()> {
    let mut marker = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    marker.write_all(contents.as_bytes())?;
    marker.sync_all()?;
    Ok(())
}

fn validate_regular_marker(path: &Path, expected: &str) -> Result<()> {
    ensure_not_link(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(DesktopError::UnsafePath(format!(
            "private staging marker is not a regular file: {}",
            path.display()
        )));
    }
    if fs::read(path)? != expected.as_bytes() {
        return Err(DesktopError::UnsafePath(format!(
            "private staging marker is missing, malformed, or bound to another pair: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Recheck the pair root and every existing ancestor immediately before an
/// open, create, rename, or publish. It rejects links/reparse points and a
/// non-directory ancestor, and never follows a target link. Windows handle-
/// relative publication would remove the final filesystem check/use interval;
/// v0.1 fails closed whenever this boundary detects a changed path.
pub fn ensure_local_operation_boundary(root: &Path, target: &Path) -> Result<()> {
    ensure_not_link(root)?;
    let relative = target.strip_prefix(root).map_err(|_| {
        DesktopError::UnsafePath(format!(
            "operation target escapes the selected local root: {}",
            target.display()
        ))
    })?;
    validate_local_relative(relative).map_err(|issue| DesktopError::UnsafePath(issue.reason))?;
    let mut current = root.to_path_buf();
    let mut ancestors = relative.components().collect::<Vec<_>>();
    ancestors.pop();
    for component in ancestors {
        let Component::Normal(name) = component else {
            return Err(DesktopError::UnsafePath(
                "operation path must have normal relative components".to_string(),
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                ensure_not_link(&current)?;
                if !metadata.is_dir() {
                    return Err(DesktopError::UnsafePath(format!(
                        "operation ancestor is not a directory: {}",
                        current.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(DesktopError::Io(error)),
        }
    }
    if target.exists() {
        ensure_not_link(target)?;
        let metadata = fs::symlink_metadata(target)?;
        if metadata.is_file() {
            let file = open_local_regular_file(target)?;
            ensure_single_linked_regular_file(&file, target)?;
        }
    }
    Ok(())
}

/// Capture the checked root and all existing ancestors/target immediately
/// before an operation can await. Call `verify_local_operation_boundary` at
/// the final mutation boundary; a changed/created/replaced path is rejected.
pub fn capture_local_operation_boundary(
    root: &Path,
    target: &Path,
) -> Result<LocalOperationBoundary> {
    ensure_local_operation_boundary(root, target)?;
    let relative = target.strip_prefix(root).map_err(|_| {
        DesktopError::UnsafePath(format!(
            "operation target escapes the selected local root: {}",
            target.display()
        ))
    })?;
    let mut existing = vec![boundary_entry(root)?];
    let mut current = root.to_path_buf();
    let mut ancestors = relative.components().collect::<Vec<_>>();
    ancestors.pop();
    for component in ancestors {
        let Component::Normal(name) = component else {
            return Err(DesktopError::UnsafePath(
                "operation path must have normal relative components".to_string(),
            ));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(_) => existing.push(boundary_entry(&current)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(DesktopError::Io(error)),
        }
    }
    let target_entry = match fs::symlink_metadata(target) {
        Ok(_) => Some(boundary_entry(target)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(DesktopError::Io(error)),
    };
    Ok(LocalOperationBoundary {
        root: root.to_path_buf(),
        target: target.to_path_buf(),
        existing,
        target_entry,
    })
}

/// Verify a saved operation boundary without following a changed path. A
/// mismatch is intentionally an unsafe-path error, not a best-effort retry:
/// callers must retain bytes and surface a review.
pub fn verify_local_operation_boundary(checkpoint: &LocalOperationBoundary) -> Result<()> {
    let current = capture_local_operation_boundary(&checkpoint.root, &checkpoint.target)?;
    if &current != checkpoint {
        return Err(DesktopError::UnsafePath(format!(
            "local path or ancestor changed while the operation was in flight: {}",
            checkpoint.target.display()
        )));
    }
    Ok(())
}

fn boundary_entry(path: &Path) -> Result<BoundaryEntry> {
    ensure_not_link(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_file() {
        let file = open_local_regular_file(path)?;
        ensure_single_linked_regular_file(&file, path)?;
    }
    Ok(BoundaryEntry {
        path: path.to_path_buf(),
        is_directory: metadata.is_dir(),
        is_file: metadata.is_file(),
        length: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

/// Reject symlinks and Windows junction/reparse points before scanning or
/// publishing any local data. The walker never follows links.
pub fn ensure_tree_has_no_links(root: &Path) -> Result<()> {
    ensure_not_link(root)?;
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry.map_err(|error| DesktopError::UnsafePath(error.to_string()))?;
        ensure_not_link(entry.path())?;
        if entry.file_type().is_file() {
            let file = open_local_regular_file(entry.path())?;
            ensure_single_linked_regular_file(&file, entry.path())?;
        }
    }
    Ok(())
}

/// Open a local leaf without waiting on a FIFO swapped in after a path check.
/// The descriptor's type is authoritative; callers check its link count too.
pub(crate) fn open_local_regular_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(DesktopError::UnsafePath(format!(
            "local file is not a regular file: {}",
            path.display()
        )));
    }
    Ok(file)
}

/// Reject a regular file with another filesystem name before its bytes cross
/// the selected-root boundary. The caller supplies the already-open handle so
/// Windows transfer sinks validate the exact object they will read or replace.
pub fn ensure_single_linked_regular_file(file: &fs::File, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(DesktopError::UnsafePath(format!(
            "local file is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(target_os = "windows")]
    if is_windows_reparse_point(&metadata) {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    if regular_file_link_count(file)? != 1 {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn regular_file_link_count(file: &fs::File) -> Result<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(u64::from(info.nNumberOfLinks))
}

#[cfg(unix)]
fn regular_file_link_count(file: &fs::File) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;

    Ok(file.metadata()?.nlink())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn regular_file_link_count(_: &fs::File) -> Result<u64> {
    Err(DesktopError::InvalidState(
        "the local filesystem cannot prove regular-file link count".to_string(),
    ))
}

pub(crate) fn ensure_not_link(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn is_windows_reparse_point(_: &fs::Metadata) -> bool {
    false
}

/// Validate a path before creating it locally. A remote name is never silently
/// rewritten: unsafe names become a review item instead of a surprising copy.
pub fn validate_local_relative(path: &Path) -> std::result::Result<(), PathIssue> {
    let components = path.components().collect::<Vec<_>>();
    if components.is_empty() || components.len() > MAX_PATH_DEPTH {
        return Err(PathIssue {
            path: path.to_path_buf(),
            reason: format!("path depth must be between 1 and {MAX_PATH_DEPTH}"),
        });
    }
    for component in components {
        let Component::Normal(name) = component else {
            return Err(PathIssue {
                path: path.to_path_buf(),
                reason: "path must be a relative normal path".to_string(),
            });
        };
        let value = name.to_string_lossy();
        if value.is_empty() || value.ends_with([' ', '.']) {
            return Err(PathIssue {
                path: path.to_path_buf(),
                reason: "a Windows name may not be empty or end with a space or period".to_string(),
            });
        }
        if value.encode_utf16().count() > MAX_WINDOWS_COMPONENT_CHARS {
            return Err(PathIssue {
                path: path.to_path_buf(),
                reason: format!(
                    "a Windows path component is longer than {MAX_WINDOWS_COMPONENT_CHARS} UTF-16 characters"
                ),
            });
        }
        if value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
        }) {
            return Err(PathIssue {
                path: path.to_path_buf(),
                reason: "name contains a character Windows cannot create".to_string(),
            });
        }
        let stem = value
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return Err(PathIssue {
                path: path.to_path_buf(),
                reason: "name is reserved by Windows".to_string(),
            });
        }
    }
    if path.to_string_lossy().encode_utf16().count() > MAX_WINDOWS_PATH_CHARS {
        return Err(PathIssue {
            path: path.to_path_buf(),
            reason: format!(
                "path is longer than {MAX_WINDOWS_PATH_CHARS} Windows UTF-16 characters"
            ),
        });
    }
    Ok(())
}

/// Accept the ordinary precomposed Latin names users expect to mirror on
/// Windows, including Latvian letters such as ā, č, ē, ģ, ī, ķ, ļ, ņ, š, ū,
/// and ž.  Combining sequences, scripts outside the proven v0.1 subset, and
/// case mappings that expand to multiple Unicode scalars are retained for
/// review: accepting them without a full Windows normalization proof could
/// alias another filesystem name.
/// Validate a relative path against the constrained Windows v0.1 character
/// policy shared by remote publication and local upload inspection.  This does
/// not mutate the filesystem and deliberately rejects unproven Unicode before
/// it can become a remote upload or a local download destination.
pub fn validate_windows_compatible_relative(path: &Path) -> std::result::Result<(), PathIssue> {
    validate_local_relative(path)?;
    let rendered = path.to_string_lossy();
    if rendered.chars().all(is_supported_windows_name_character) {
        Ok(())
    } else {
        Err(PathIssue {
            path: path.to_path_buf(),
            reason: "contains Unicode whose Windows normalization or case mapping is not safely supported in v0.1"
                .to_string(),
        })
    }
}

pub(super) fn is_supported_windows_name_character(character: char) -> bool {
    if character.is_ascii() {
        return true;
    }
    let codepoint = character as u32;
    let precomposed_latin =
        (0x00c0..=0x024f).contains(&codepoint) || (0x1e00..=0x1eff).contains(&codepoint);
    let mut lowercase = character.to_lowercase();
    let mut uppercase = character.to_uppercase();
    let (Some(lowercase), Some(uppercase)) = (lowercase.next(), uppercase.next()) else {
        return false;
    };
    precomposed_latin
        && lowercase.to_uppercase().eq(std::iter::once(uppercase))
        && uppercase.to_lowercase().eq(std::iter::once(lowercase))
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_paths_compare_ignore_case(left: &Path, right: &Path) -> std::cmp::Ordering {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CompareStringOrdinal(
            left: *const u16,
            left_len: i32,
            right: *const u16,
            right_len: i32,
            ignore_case: i32,
        ) -> i32;
    }

    const CSTR_LESS_THAN: i32 = 1;
    const CSTR_EQUAL: i32 = 2;
    const CSTR_GREATER_THAN: i32 = 3;
    let left = left.to_string_lossy().encode_utf16().collect::<Vec<_>>();
    let right = right.to_string_lossy().encode_utf16().collect::<Vec<_>>();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return left.cmp(&right);
    };
    // CompareStringOrdinal is the Windows ordinal case-insensitive comparison
    // used for this conservative pre-publication collision check.  The input
    // is trusted Rust UTF-16 derived from validated remote strings.
    match unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) } {
        CSTR_LESS_THAN => std::cmp::Ordering::Less,
        CSTR_EQUAL => std::cmp::Ordering::Equal,
        CSTR_GREATER_THAN => std::cmp::Ordering::Greater,
        _ => left.cmp(&right),
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn windows_paths_compare_ignore_case(left: &Path, right: &Path) -> std::cmp::Ordering {
    // Host tests exercise the same constrained character set.  The Windows
    // build swaps this for CompareStringOrdinal above.
    left.to_string_lossy()
        .to_lowercase()
        .cmp(&right.to_string_lossy().to_lowercase())
}

pub fn windows_paths_equal_ignore_case(left: &Path, right: &Path) -> bool {
    windows_paths_compare_ignore_case(left, right).is_eq()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::{RemoteEntry, RemoteEntryKind};

    #[cfg(unix)]
    #[test]
    fn local_regular_file_open_rejects_fifo_and_links_and_preserves_bytes() {
        use std::{
            ffi::CString,
            io::Read,
            os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
            sync::mpsc,
        };

        let directory = tempfile::tempdir().unwrap();
        let regular = directory.path().join("regular.txt");
        fs::write(&regular, b"regular bytes").unwrap();
        let mut bytes = String::new();
        open_local_regular_file(&regular)
            .unwrap()
            .read_to_string(&mut bytes)
            .unwrap();
        assert_eq!(bytes, "regular bytes");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&regular, &link).unwrap();
        assert!(open_local_regular_file(&link).is_err());
        assert!(open_local_regular_file(directory.path()).is_err());

        let fifo = directory.path().join("fifo");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let path = fifo.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            sender
                .send(open_local_regular_file(&path).map(|_| ()))
                .unwrap();
        });
        let result = receiver.recv_timeout(Duration::from_secs(1));
        // Unblock a regressed opener before asserting the bounded result.
        let release = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        worker.join().unwrap();
        drop(release);
        assert!(matches!(
            result.expect("FIFO open must not wait for a writer"),
            Err(DesktopError::UnsafePath(_))
        ));
    }

    fn remote(id: &str, parent_id: Option<&str>, name: &str) -> RemoteEntry {
        RemoteEntry {
            id: id.into(),
            parent_id: parent_id.map(str::to_owned),
            name: name.into(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some(id.into()),
            size_bytes: Some(1),
            trashed: false,
        }
    }

    #[test]
    fn rejects_windows_reserved_names_and_case_collisions() {
        assert!(validate_local_relative(Path::new("AUX.txt")).is_err());
        let entries = vec![
            remote("a", None, "Report.txt"),
            remote("b", None, "report.txt"),
        ];
        assert!(matches!(
            map_remote_paths(&entries, None),
            Err(DesktopError::CaseCollision(_))
        ));
        let unicode_entries = vec![
            remote("upper", None, "Ä.txt"),
            remote("lower", None, "ä.txt"),
        ];
        assert!(matches!(
            map_remote_paths(&unicode_entries, None),
            Err(DesktopError::CaseCollision(_))
        ));
        let exact_duplicate_entries = vec![
            remote("first", None, "same.txt"),
            remote("second", None, "same.txt"),
        ];
        assert!(matches!(
            map_remote_paths(&exact_duplicate_entries, None),
            Err(DesktopError::CaseCollision(_))
        ));
    }

    #[test]
    fn accepts_ordinary_precomposed_latin_and_latvian_names() {
        let entries = vec![
            RemoteEntry {
                id: "folder".into(),
                parent_id: None,
                name: "Rīga".into(),
                kind: RemoteEntryKind::Folder,
                revision: 1,
                content_hash: None,
                size_bytes: None,
                trashed: false,
            },
            remote("file", Some("folder"), "Ābols un Žanis - résumé.txt"),
        ];
        let mapping = inspect_remote_paths(&entries, None).unwrap();
        assert!(mapping.issues.is_empty());
        assert_eq!(
            mapping.paths["file"],
            PathBuf::from("Rīga/Ābols un Žanis - résumé.txt")
        );
        assert_eq!(map_remote_paths(&entries, None).unwrap(), mapping.paths);
    }

    #[test]
    fn rejects_asymmetric_latin_case_mappings_before_windows_publication() {
        assert!(validate_windows_compatible_relative(Path::new("long-ſ.txt")).is_err());
    }

    #[test]
    fn returns_stable_manifest_issues_for_incompatible_windows_paths() {
        let long_component = "x".repeat(MAX_WINDOWS_COMPONENT_CHARS + 1);
        let long_prefix = "p".repeat(130);
        let long_leaf = "q".repeat(110);
        let entries = vec![
            remote("reserved", None, "AUX.txt"),
            remote("trailing", None, "draft. "),
            remote("component", None, &long_component),
            RemoteEntry {
                id: "long-parent".into(),
                parent_id: None,
                name: long_prefix,
                kind: RemoteEntryKind::Folder,
                revision: 1,
                content_hash: None,
                size_bytes: None,
                trashed: false,
            },
            remote("long-path", Some("long-parent"), &long_leaf),
            remote("exact-a", None, "same.txt"),
            remote("exact-b", None, "same.txt"),
            remote("case-a", None, "Report.txt"),
            remote("case-b", None, "report.txt"),
            remote("unicode", None, "Cafe\u{301}.txt"),
        ];

        let first = inspect_remote_paths(&entries, None).unwrap();
        let mut reversed = entries.clone();
        reversed.reverse();
        let second = inspect_remote_paths(&reversed, None).unwrap();
        assert_eq!(first.issues, second.issues);
        assert_eq!(first.paths.len(), 1);
        assert_eq!(first.paths["long-parent"], PathBuf::from("p".repeat(130)));
        assert_eq!(first.issues.len(), 9);
        assert!(first.issues.iter().any(|issue| {
            issue.path == Path::new("AUX.txt") && issue.reason == "name is reserved by Windows"
        }));
        assert!(first.issues.iter().any(|issue| {
            issue.path == Path::new("draft. ")
                && issue.reason.contains("end with a space or period")
        }));
        assert!(first
            .issues
            .iter()
            .any(|issue| issue.remote_id == "component" && issue.reason.contains("component")));
        assert!(
            first
                .issues
                .iter()
                .any(|issue| issue.remote_id == "long-path"
                    && issue.reason.contains("path is longer"))
        );
        assert_eq!(
            first
                .issues
                .iter()
                .filter(|issue| issue.reason == "two Drive items map to this exact Windows path")
                .count(),
            2
        );
        assert_eq!(
            first
                .issues
                .iter()
                .filter(|issue| issue.reason.contains("case-insensitively"))
                .count(),
            2
        );
        assert!(first.issues.iter().any(|issue| {
            issue.path == Path::new("Cafe\u{301}.txt")
                && issue.reason.contains("normalization or case mapping")
        }));
        assert!(matches!(
            map_remote_paths(&entries, None),
            Err(DesktopError::UnsafePath(_)) | Err(DesktopError::CaseCollision(_))
        ));
    }

    #[test]
    fn rejects_duplicate_remote_ids_without_silently_rebinding_a_path() {
        let entries = vec![
            remote("same-id", None, "first.txt"),
            remote("same-id", None, "second.txt"),
        ];
        assert!(matches!(
            inspect_remote_paths(&entries, None),
            Err(DesktopError::InvalidState(message)) if message.contains("duplicate item id: same-id")
        ));
    }

    #[test]
    fn selected_folder_is_the_local_root() {
        let entries = vec![
            RemoteEntry {
                id: "folder".into(),
                parent_id: None,
                name: "Product".into(),
                kind: RemoteEntryKind::Folder,
                revision: 1,
                content_hash: None,
                size_bytes: None,
                trashed: false,
            },
            remote("child", Some("folder"), "readme.md"),
        ];
        let paths = map_remote_paths(&entries, Some("folder")).unwrap();
        assert_eq!(paths["child"], PathBuf::from("readme.md"));
        assert!(!paths.contains_key("folder"));
    }

    #[test]
    fn hostile_remote_path_expansion_is_rejected_before_retaining_large_paths() {
        let oversized_name = "x".repeat(2 * 1024 * 1024);
        let entries = vec![remote("oversized", None, &oversized_name)];
        let mapping = inspect_remote_paths(&entries, None).unwrap();
        assert!(mapping.paths.is_empty());
        assert_eq!(mapping.issues.len(), 1);
        assert_eq!(mapping.issues[0].remote_id, "oversized");
        assert!(mapping.issues[0].path.as_os_str().is_empty());
        assert!(mapping.issues[0].reason.contains("component"));

        let mut deep = Vec::new();
        let mut parent = None;
        for index in 0..(MAX_PATH_DEPTH + 4) {
            let id = format!("deep-{index}");
            deep.push(RemoteEntry {
                id: id.clone(),
                parent_id: parent,
                name: "n".to_string(),
                kind: RemoteEntryKind::Folder,
                revision: 1,
                content_hash: None,
                size_bytes: None,
                trashed: false,
            });
            parent = Some(id);
        }
        let mapping = inspect_remote_paths(&deep, None).unwrap();
        assert!(mapping
            .issues
            .iter()
            .any(|issue| issue.reason.contains("path depth")
                || issue.reason.contains("path is longer")));
        assert!(mapping.issues.iter().all(|issue| {
            issue.path.to_string_lossy().encode_utf16().count() <= MAX_WINDOWS_PATH_CHARS
        }));
    }

    #[test]
    fn operation_boundary_rejects_a_non_directory_ancestor() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("pair");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("ordinary-file"), b"bytes").unwrap();
        assert!(
            ensure_local_operation_boundary(&root, &root.join("ordinary-file/child.txt")).is_err()
        );
    }

    #[test]
    fn operation_checkpoint_rejects_a_created_target_after_a_network_gap() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("pair");
        fs::create_dir(&root).unwrap();
        let target = root.join("report.txt");
        let checkpoint = capture_local_operation_boundary(&root, &target).unwrap();
        fs::write(&target, b"user-created-after-scan").unwrap();
        assert!(verify_local_operation_boundary(&checkpoint).is_err());
    }

    #[test]
    fn strict_tree_rejects_a_multiply_linked_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("pair");
        fs::create_dir(&root).unwrap();
        let outside = directory.path().join("outside.txt");
        fs::write(&outside, b"outside bytes").unwrap();
        fs::hard_link(&outside, root.join("inside.txt")).unwrap();
        assert!(matches!(
            ensure_tree_has_no_links(&root),
            Err(DesktopError::UnsafeLink(_))
        ));
    }

    fn staging_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let pair = directory.path().join("pair");
        fs::create_dir(&pair).unwrap();
        let staging = upload_staging_root(&pair).unwrap();
        (directory, pair, staging)
    }

    #[test]
    fn unmarked_preexisting_staging_root_is_refused_without_touching_content() {
        let (_directory, pair, staging) = staging_fixture();
        fs::create_dir(&staging).unwrap();
        let user_file = staging.join("not-ours.txt");
        fs::write(&user_file, b"preserve").unwrap();
        assert!(initialize_owned_staging_root(&pair, &staging, "upload").is_err());
        assert_eq!(fs::read(&user_file).unwrap(), b"preserve");
    }

    #[test]
    fn marked_root_with_arbitrary_child_fails_closed_and_leaves_it_untouched() {
        let (_directory, pair, staging) = staging_fixture();
        let area = initialize_owned_staging_root(&pair, &staging, "upload").unwrap();
        let arbitrary = staging.join("old-user-content");
        fs::write(&arbitrary, b"preserve").unwrap();
        assert!(area.cleanup_aged_batches(Duration::ZERO).is_err());
        assert_eq!(fs::read(&arbitrary).unwrap(), b"preserve");
    }

    #[test]
    fn spoofed_batch_name_without_marker_is_refused_and_untouched() {
        let (_directory, pair, staging) = staging_fixture();
        let area = initialize_owned_staging_root(&pair, &staging, "upload").unwrap();
        let spoof = staging
            .join("shellx-drive-upload-batch-v1-00000000000000000000-00000000000000000000-00");
        fs::create_dir(&spoof).unwrap();
        fs::write(spoof.join("payload"), b"preserve").unwrap();
        assert!(area.cleanup_aged_batches(Duration::ZERO).is_err());
        assert_eq!(fs::read(spoof.join("payload")).unwrap(), b"preserve");
    }

    #[test]
    fn valid_owned_old_batch_is_the_only_batch_cleanup_removes() {
        let (_directory, pair, staging) = staging_fixture();
        let area = initialize_owned_staging_root(&pair, &staging, "upload").unwrap();
        let batch = area.create_batch(7).unwrap();
        fs::write(batch.join("payload"), b"owned").unwrap();
        assert_eq!(area.cleanup_aged_batches(Duration::ZERO).unwrap(), 1);
        assert!(!batch.exists());
    }

    #[test]
    fn retained_recovery_batch_is_never_aged_out_or_removed() {
        let (_directory, pair, staging) = staging_fixture();
        let area = initialize_owned_staging_root(&pair, &staging, "download").unwrap();
        let batch = area.create_batch(8).unwrap();
        let payload = batch.join("previous-local");
        fs::write(&payload, b"preserve-local-bytes").unwrap();
        area.retain_batch(&batch).unwrap();

        assert_eq!(area.cleanup_aged_batches(Duration::ZERO).unwrap(), 0);
        assert_eq!(fs::read(&payload).unwrap(), b"preserve-local-bytes");
        assert!(area.remove_batch(&batch).is_err());
    }

    #[test]
    fn wrong_pair_binding_is_refused_without_altering_the_existing_root() {
        let (directory, pair, staging) = staging_fixture();
        let area = initialize_owned_staging_root(&pair, &staging, "upload").unwrap();
        let marker = staging.join(STAGING_ROOT_MARKER);
        let before = fs::read(&marker).unwrap();
        let other_pair = directory.path().join("other-pair");
        fs::create_dir(&other_pair).unwrap();
        assert!(initialize_owned_staging_root(&other_pair, &staging, "upload").is_err());
        assert_eq!(fs::read(&marker).unwrap(), before);
        drop(area);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_staging_root_is_refused_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let (directory, pair, staging) = staging_fixture();
        let target = directory.path().join("unrelated");
        fs::create_dir(&target).unwrap();
        let preserved = target.join("preserve.txt");
        fs::write(&preserved, b"preserve").unwrap();
        symlink(&target, &staging).unwrap();
        assert!(initialize_owned_staging_root(&pair, &staging, "upload").is_err());
        assert_eq!(fs::read(&preserved).unwrap(), b"preserve");
    }
}

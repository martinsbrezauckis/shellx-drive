//! Handle-bound guard and move-aside transaction for inbound replacements.

use std::{
    fs,
    mem::size_of,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use shellx_drive_desktop_core::{
    hash_reader_bounded, DesktopError, LocalEntry, LocalScanLimits, OwnedStagingRoot, ReadBudget,
    Result as CoreResult,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_READ},
    Storage::FileSystem::{
        FileDispositionInfo, FileIdInfo, GetFileInformationByHandleEx, SetFileInformationByHandle,
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    },
};

use super::{
    transfer_execution::{
        open_checked_rename_target_directory, pin_checked_rename_directory_chain,
    },
    verified_staging::{move_verified_staged_file, rename_open_file_at, VerifiedStagedFile},
};

static NEXT_RECOVERY_LEAF: AtomicU64 = AtomicU64::new(0);

pub(super) enum ReplacementOutcome {
    Published,
    NeedsReview { recovery_leaf: Option<String> },
}

pub(super) struct FrozenDestination {
    file: fs::File,
    entry: LocalEntry,
    volume_serial: u64,
    _parent_pins: Vec<fs::File>,
    parent: fs::File,
}

impl FrozenDestination {
    pub(super) fn open(
        root: &Path,
        destination: &Path,
        relative_path: &Path,
        budget: &mut ReadBudget,
    ) -> CoreResult<Self> {
        let parent = destination.parent().ok_or_else(|| {
            DesktopError::UnsafePath("replacement destination has no parent".to_string())
        })?;
        let parent_pins = pin_checked_rename_directory_chain(root, parent)?;
        let parent_handle = open_checked_rename_target_directory(parent, false)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .access_mode(GENERIC_READ | DELETE | FILE_READ_ATTRIBUTES)
            // Existing writers/deleters make this open fail; new ones remain
            // blocked until the exact hashed object is moved or restored.
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(destination)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(DesktopError::UnsafePath(format!(
                "replacement destination is not a regular non-reparse file: {}",
                destination.display()
            )));
        }
        shellx_drive_desktop_core::ensure_single_linked_regular_file(&file, destination)?;
        let max_file_bytes = LocalScanLimits::default().max_file_bytes;
        if metadata.len() > max_file_bytes {
            return Err(DesktopError::InvalidState(format!(
                "local file exceeds the {max_file_bytes}-byte scan limit: {}",
                relative_path.display()
            )));
        }
        budget.charge(metadata.len())?;
        let (content_hash, actual_bytes) = hash_reader_bounded(&mut file, metadata.len())?;
        if actual_bytes != metadata.len() {
            return Err(DesktopError::InvalidState(
                "locked replacement target changed while it was read".to_string(),
            ));
        }
        let volume_serial = file_volume_serial(&file)?;
        Ok(Self {
            file,
            entry: LocalEntry {
                relative_path: relative_path.to_path_buf(),
                content_hash: Some(content_hash),
                size_bytes: actual_bytes,
                is_directory: false,
                directory_identity: None,
            },
            volume_serial,
            _parent_pins: parent_pins,
            parent: parent_handle,
        })
    }

    pub(super) fn entry(&self) -> &LocalEntry {
        &self.entry
    }

    fn parent(&self) -> CoreResult<&fs::File> {
        Ok(&self.parent)
    }
}

fn file_volume_serial(file: &fs::File) -> CoreResult<u64> {
    let mut info = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(info.VolumeSerialNumber)
}

fn move_frozen_to_recovery<F>(
    destination: &Path,
    frozen: &FrozenDestination,
    before_move: F,
) -> CoreResult<PathBuf>
where
    F: FnOnce() -> CoreResult<()>,
{
    before_move()?;
    let parent = destination.parent().ok_or_else(|| {
        DesktopError::UnsafePath("replacement destination has no parent".to_string())
    })?;
    let unique = NEXT_RECOVERY_LEAF.fetch_add(1, Ordering::AcqRel);
    for retry in 0..8_u8 {
        let leaf = format!(
            ".shellx-drive-replaced-{}-{unique:020}-{retry:02}",
            std::process::id()
        );
        match rename_open_file_at(&frozen.file, frozen.parent()?, leaf.as_ref(), false) {
            Ok(()) => return Ok(parent.join(leaf)),
            Err(DesktopError::Io(error))
                if matches!(
                    error.raw_os_error(),
                    Some(code)
                        if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Err(DesktopError::InvalidState(
        "could not allocate a collision-free replacement recovery leaf".to_string(),
    ))
}

fn delete_open_file(file: &fs::File) -> CoreResult<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

// The two callbacks mark separate race boundaries; keep all witnesses explicit
// instead of hiding them inside a reusable context that could outlive either.
#[allow(clippy::too_many_arguments)]
pub(super) fn publish_replacing_staged_file<F, G>(
    root: &Path,
    destination: &Path,
    staged: &Path,
    verified: &VerifiedStagedFile,
    staging: Option<(&OwnedStagingRoot, &Path)>,
    frozen: FrozenDestination,
    before_move: F,
    before_publish: G,
) -> CoreResult<ReplacementOutcome>
where
    F: FnOnce() -> CoreResult<()>,
    G: FnOnce() -> CoreResult<()>,
{
    if file_volume_serial(&verified.0)? != frozen.volume_serial {
        return Ok(ReplacementOutcome::NeedsReview {
            recovery_leaf: None,
        });
    }
    let recovery = match move_frozen_to_recovery(destination, &frozen, before_move) {
        Ok(path) => path,
        Err(_) => {
            return Ok(ReplacementOutcome::NeedsReview {
                recovery_leaf: None,
            });
        }
    };
    let staged_parent = staged.parent().ok_or_else(|| {
        DesktopError::UnsafePath("staged replacement has no private batch parent".to_string())
    })?;
    if move_verified_staged_file(
        staged_parent,
        staged,
        verified,
        destination,
        root,
        false,
        before_publish,
    )
    .is_err()
    {
        let original_leaf = destination.file_name().ok_or_else(|| {
            DesktopError::UnsafePath("replacement destination has no leaf".to_string())
        })?;
        if rename_open_file_at(&frozen.file, frozen.parent()?, original_leaf, false).is_err() {
            if let Some((staging_area, batch)) = staging {
                let _ = staging_area.retain_batch(batch);
            }
            return Ok(ReplacementOutcome::NeedsReview {
                recovery_leaf: recovery
                    .file_name()
                    .and_then(|leaf| leaf.to_str())
                    .map(str::to_string),
            });
        }
        return Ok(ReplacementOutcome::NeedsReview {
            recovery_leaf: None,
        });
    }

    let cleanup = delete_open_file(&frozen.file);
    drop(frozen);
    let removed = matches!(
        fs::symlink_metadata(&recovery),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    if cleanup.is_err() || !removed {
        return Ok(ReplacementOutcome::NeedsReview {
            recovery_leaf: recovery
                .file_name()
                .and_then(|leaf| leaf.to_str())
                .map(str::to_string),
        });
    }
    Ok(ReplacementOutcome::Published)
}

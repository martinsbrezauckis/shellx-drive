//! Physical Windows identity guard for configured desktop sync roots.

use std::{fs, mem::size_of, os::windows::io::AsRawHandle, path::Path};

use shellx_drive_desktop_core::{
    DesktopError, DesktopState, PairMarker, Result as CoreResult, WindowsDirectoryIdentity,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
};

use super::pair_marker;
use super::transfer_execution::pin_absolute_directory_chain;

pub(super) struct PairRootGuard {
    pub(super) required_identity: WindowsDirectoryIdentity,
    pub(super) _chains: Vec<DirectoryIdentityChain>,
}

pub(super) struct DirectoryIdentityChain {
    pub(super) path: std::path::PathBuf,
    pub(super) identities: Vec<WindowsDirectoryIdentity>,
    _handles: Vec<fs::File>,
}

/// Pin every available configured root and reject physical equality or
/// containment. The selected/new root is mandatory; an absent inactive root
/// is harmless until it becomes available, when every action checks again.
pub(super) fn guard_configured_pair_roots(
    state: &DesktopState,
    required_root: &Path,
) -> CoreResult<PairRootGuard> {
    let mut roots = state
        .pairs()
        .map(|pair| pair.local_root.clone())
        .collect::<Vec<_>>();
    if !roots.iter().any(|root| root == required_root) {
        roots.push(required_root.to_path_buf());
    }
    let mut chains = Vec::with_capacity(roots.len());
    for root in roots {
        let required = root == required_root;
        match open_identity_chain(&root) {
            Ok(chain) => chains.push(chain),
            Err(DesktopError::Io(error))
                if !required && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    reject_overlapping_chains(&chains)?;
    let required_identity = chains
        .iter()
        .find(|chain| chain.path == required_root)
        .and_then(|chain| chain.identities.last())
        .cloned()
        .ok_or_else(|| missing_root_identity("selected"))?;
    if let Some(pair) = state.pairs().find(|pair| pair.local_root == required_root) {
        verify_expected_root(
            required_root,
            &required_identity,
            pair.local_root_identity.as_ref(),
            &PairMarker::from(pair),
        )?;
    }
    Ok(PairRootGuard {
        required_identity,
        _chains: chains,
    })
}

pub(super) fn guard_disconnected_pair_root(
    root: &Path,
    marker: &PairMarker,
) -> CoreResult<PairRootGuard> {
    let chain = open_identity_chain(root)?;
    let required_identity = chain
        .identities
        .last()
        .cloned()
        .ok_or_else(|| missing_root_identity("disconnected"))?;
    verify_expected_identity(
        root,
        &required_identity,
        marker.local_root_identity.as_ref(),
    )?;
    pair_marker::require_exact_or_absent(root, marker)?;
    Ok(PairRootGuard {
        required_identity,
        _chains: vec![chain],
    })
}

pub(super) fn missing_root_identity(kind: &str) -> DesktopError {
    DesktopError::InvalidState(format!("the {kind} Drive root has no Windows identity"))
}

fn verify_expected_root(
    root: &Path,
    current: &WindowsDirectoryIdentity,
    expected: Option<&WindowsDirectoryIdentity>,
    marker: &PairMarker,
) -> CoreResult<()> {
    verify_expected_identity(root, current, expected)?;
    pair_marker::require_exact(root, marker)
}

fn verify_expected_identity(
    root: &Path,
    current: &WindowsDirectoryIdentity,
    expected: Option<&WindowsDirectoryIdentity>,
) -> CoreResult<()> {
    let expected = expected.ok_or_else(|| {
        DesktopError::InvalidState(
            "this Drive location predates physical root binding; pair the folder again".to_string(),
        )
    })?;
    if current != expected {
        return Err(DesktopError::UnsafePath(format!(
            "the configured Drive folder was replaced: {}",
            root.display()
        )));
    }
    Ok(())
}

pub(super) fn open_identity_chain(path: &Path) -> CoreResult<DirectoryIdentityChain> {
    let handles = pin_absolute_directory_chain(path)?;
    let identities = handles
        .iter()
        .map(directory_identity)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(DirectoryIdentityChain {
        path: path.to_path_buf(),
        identities,
        _handles: handles,
    })
}

/// Compare native physical ancestry across independent connection containers.
/// No-follow handles remain live for the complete comparison.
pub(crate) fn validate_connection_folder_identity(
    candidate: &Path,
    reserved: &Path,
) -> CoreResult<()> {
    let candidate = open_identity_chain(candidate)?;
    let reserved = match open_identity_chain(reserved) {
        Ok(chain) => chain,
        Err(DesktopError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(())
        }
        Err(error) => return Err(error),
    };
    reject_overlapping_chains(&[candidate, reserved])
}

fn directory_identity(file: &fs::File) -> CoreResult<WindowsDirectoryIdentity> {
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
    Ok(WindowsDirectoryIdentity::windows(
        info.VolumeSerialNumber,
        info.FileId.Identifier,
    ))
}

fn reject_overlapping_chains(chains: &[DirectoryIdentityChain]) -> CoreResult<()> {
    for (index, left) in chains.iter().enumerate() {
        let left_root = left
            .identities
            .last()
            .ok_or_else(|| missing_root_identity("configured"))?;
        for right in chains.iter().skip(index + 1) {
            let right_root = right
                .identities
                .last()
                .ok_or_else(|| missing_root_identity("configured"))?;
            if right.identities.contains(left_root) || left.identities.contains(right_root) {
                return Err(DesktopError::InvalidState(format!(
                    "configured local Drive folders resolve to the same or nested Windows directory: {} and {}",
                    left.path.display(),
                    right.path.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "pair_root_identity_tests.rs"]
mod tests;

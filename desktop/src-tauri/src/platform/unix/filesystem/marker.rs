//! Exact, non-secret pairing-marker lifecycle below a selected root descriptor.

use std::{
    ffi::{OsStr, OsString},
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use shellx_drive_desktop_core::{
    ensure_single_linked_regular_file, DesktopError, PairMarker, PairMarkerDisposition,
    Result as CoreResult,
};

use super::{
    descriptor::{create_regular_file_at, open_regular_file_at, unlink_at},
    UnixRootGuard,
};

pub(super) const PAIR_MARKER_FILE: &str = ".shellx-drive-pair.json";
const MAX_MARKER_BYTES: u64 = 64 * 1024;
static NEXT_MARKER_TEMP: AtomicU64 = AtomicU64::new(0);

pub(super) fn write_or_recognize(
    guard: &UnixRootGuard,
    marker: &PairMarker,
) -> CoreResult<PairMarkerDisposition> {
    if let Some(existing) = read_marker(guard)? {
        return if existing == *marker {
            Ok(PairMarkerDisposition::ExistingIdentical)
        } else {
            Err(DesktopError::UnsafePath(
                "pair marker belongs to another Drive location".to_string(),
            ))
        };
    }
    let bytes = serde_json::to_vec(marker)?;
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(DesktopError::InvalidState(
            "pair marker exceeds its size limit".to_string(),
        ));
    }
    let temporary = OsString::from(format!(
        ".shellx-drive-pair.{}.{}.next",
        std::process::id(),
        NEXT_MARKER_TEMP.fetch_add(1, Ordering::AcqRel)
    ));
    let result = (|| {
        let mut file = create_regular_file_at(&guard.root, &temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        super::descriptor::link_at(
            &guard.root,
            &temporary,
            &guard.root,
            OsStr::new(PAIR_MARKER_FILE),
        )?;
        unlink_at(&guard.root, &temporary)
    })();
    if result.is_err() {
        let _ = unlink_at(&guard.root, &temporary);
    }
    result.map(|()| PairMarkerDisposition::Created)
}

pub(super) fn require_exact(guard: &UnixRootGuard, marker: &PairMarker) -> CoreResult<()> {
    match read_marker(guard)? {
        Some(existing) if existing == *marker => Ok(()),
        _ => Err(DesktopError::InvalidState(
            "the configured Drive folder marker is missing; pair the folder again".to_string(),
        )),
    }
}

pub(super) fn remove_exact(guard: &UnixRootGuard, marker: &PairMarker) -> CoreResult<bool> {
    match read_marker(guard)? {
        None => Ok(false),
        Some(existing) if existing == *marker => {
            unlink_at(&guard.root, OsStr::new(PAIR_MARKER_FILE))?;
            Ok(true)
        }
        Some(_) => Err(DesktopError::UnsafePath(
            "refusing to remove a pair marker owned by another Drive location".to_string(),
        )),
    }
}

fn read_marker(guard: &UnixRootGuard) -> CoreResult<Option<PairMarker>> {
    let mut file = match open_regular_file_at(&guard.root, OsStr::new(PAIR_MARKER_FILE)) {
        Ok(file) => file,
        Err(DesktopError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    ensure_single_linked_regular_file(&file, Path::new(PAIR_MARKER_FILE))?;
    let size = file.metadata()?.len();
    if size > MAX_MARKER_BYTES {
        return Err(DesktopError::UnsafePath(
            "pair marker exceeds its size limit".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(MAX_MARKER_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(DesktopError::UnsafePath(
            "pair marker exceeds its size limit".to_string(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| DesktopError::UnsafePath("pair marker is malformed".to_string()))
}

//! Cross-connection folder ownership checked before native admission.

use shellx_drive_desktop_core::{DesktopError, Result as CoreResult};
use std::path::{Path, PathBuf};

/// Existing sync roots retain their native recorded identity and marker.
/// A disconnected disk belonging to another connection need not stop their
/// checks. New admission uses the stricter helper below.
pub(crate) fn ensure_existing_folder_separate(
    candidate: &Path,
    reservations: &[(String, PathBuf)],
) -> CoreResult<()> {
    for (owner, reserved) in reservations {
        if lexical_overlap(candidate, reserved) {
            return Err(folder_conflict(owner));
        }
    }
    let available = reservations
        .iter()
        .filter(|(_, path)| path.exists())
        .cloned()
        .collect::<Vec<_>>();
    ensure_separate_folder(candidate, &available)
}

pub(crate) fn ensure_separate_folder(
    candidate: &Path,
    reservations: &[(String, PathBuf)],
) -> CoreResult<()> {
    if !candidate.is_absolute() || !candidate.is_dir() {
        return Err(DesktopError::InvalidState(
            "Choose an existing empty local folder with Browse.".into(),
        ));
    }
    let candidate_canonical = candidate.canonicalize()?;
    for (owner, reserved) in reservations {
        let conflict =
            lexical_overlap(candidate, reserved) || lexical_overlap(&candidate_canonical, reserved);
        if conflict {
            return Err(folder_conflict(owner));
        }
        // An unavailable reservation remains owned. In particular, a removed
        // disk must never be interpreted as an unconfigured connection.
        let reserved_canonical = reserved.canonicalize().map_err(|_| {
            DesktopError::InvalidState(format!(
                "Drive cannot verify the folder owned by {owner}. Reconnect its disk before choosing another local folder."
            ))
        })?;
        if lexical_overlap(&candidate_canonical, &reserved_canonical) {
            return Err(folder_conflict(owner));
        }
        #[cfg(unix)]
        if physical_overlap(&candidate_canonical, &reserved_canonical)? {
            return Err(folder_conflict(owner));
        }
        #[cfg(target_os = "windows")]
        crate::application::windows::validate_connection_folder_identity(
            &candidate_canonical,
            &reserved_canonical,
        )
        .map_err(|_| folder_conflict(owner))?;
    }
    Ok(())
}

fn folder_conflict(owner: &str) -> DesktopError {
    DesktopError::InvalidState(format!(
        "Choose a separate folder. This location belongs to {owner}."
    ))
}

fn lexical_overlap(left: &Path, right: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let normalize = |path: &Path| {
            path.components()
                .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
                .collect::<Vec<_>>()
        };
        let left = normalize(left);
        let right = normalize(right);
        left.starts_with(&right) || right.starts_with(&left)
    }
    #[cfg(not(target_os = "windows"))]
    {
        left.starts_with(right) || right.starts_with(left)
    }
}

#[cfg(unix)]
fn physical_overlap(left: &Path, right: &Path) -> CoreResult<bool> {
    use std::os::unix::fs::MetadataExt;
    fn identity(path: &Path) -> CoreResult<(u64, u64)> {
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_dir() {
            return Err(DesktopError::InvalidState(
                "A reserved Drive folder is not a directory.".into(),
            ));
        }
        Ok((metadata.dev(), metadata.ino()))
    }
    let left_identity = identity(left)?;
    let right_identity = identity(right)?;
    for ancestor in left.ancestors() {
        if identity(ancestor)? == right_identity {
            return Ok(true);
        }
    }
    for ancestor in right.ancestors() {
        if identity(ancestor)? == left_identity {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn equal_nested_and_parent_folders_conflict_but_siblings_work() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("Work");
        let nested = work.join("Projects");
        let personal = dir.path().join("Personal");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir(&personal).unwrap();
        let owned = vec![("Work".into(), work.clone())];
        for candidate in [&work, &nested, &dir.path().to_path_buf()] {
            assert!(ensure_separate_folder(candidate, &owned)
                .unwrap_err()
                .to_string()
                .contains("belongs to Work"));
        }
        ensure_separate_folder(&personal, &owned).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn physical_alias_to_a_reserved_folder_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("Work");
        let alias = dir.path().join("alias");
        std::fs::create_dir(&work).unwrap();
        std::os::unix::fs::symlink(&work, &alias).unwrap();
        assert!(ensure_separate_folder(&alias, &[("Work".into(), work)]).is_err());
    }
}

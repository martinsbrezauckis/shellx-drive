//! Descriptor-bound Unix local-root boundary.
//!
//! The public guard deliberately exposes no path-string mutation escape hatch.
//! Its focused child modules handle descriptor opening, pairing markers, and
//! publication while callers remain rooted in this verified descriptor.

use std::{fs, path::Path};

#[cfg(any(target_os = "linux", test))]
use shellx_drive_desktop_core::windows_paths_equal_ignore_case;
use shellx_drive_desktop_core::{
    DirectoryIdentity, PairMarker, PairMarkerDisposition, Result as CoreResult,
};

mod descriptor;
mod marker;
mod mutation;
mod publication;

#[cfg(target_os = "linux")]
pub(crate) use mutation::LinuxPreparedReplacement;

#[cfg(target_os = "macos")]
pub(crate) use mutation::MacOsPreparedReplacement;

#[cfg(test)]
pub(crate) struct TestFixtureDirectory {
    _temporary: tempfile::TempDir,
    physical_path: std::path::PathBuf,
}

#[cfg(test)]
impl TestFixtureDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.physical_path
    }
}

#[cfg(test)]
pub(crate) fn test_fixture_directory() -> TestFixtureDirectory {
    let temporary = tempfile::tempdir().expect("create temporary test fixture directory");
    let physical_path = temporary
        .path()
        .canonicalize()
        .expect("canonicalize temporary test fixture directory");
    TestFixtureDirectory {
        _temporary: temporary,
        physical_path,
    }
}

#[cfg(test)]
mod tests;

/// A selected root pinned by an opened descriptor. Its saved identity is
/// platform tagged, so a legacy NTFS record cannot be adopted on Unix.
pub(crate) struct UnixRootGuard {
    pub(super) root: fs::File,
    pub(super) identity: DirectoryIdentity,
    pub(super) path: std::path::PathBuf,
}

/// A local replacement either completed with the previous bytes removed only
/// after the new bytes were published, or it stopped with an explicit recovery
/// leaf.  Callers retain their private staged batch for the latter outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReplacingPublication {
    Published,
    NeedsReview { recovery_leaf: Option<String> },
}

impl UnixRootGuard {
    pub(crate) fn acquire(root: &Path, expected: Option<&DirectoryIdentity>) -> CoreResult<Self> {
        descriptor::acquire(root, expected)
    }

    pub(crate) fn identity(&self) -> &DirectoryIdentity {
        &self.identity
    }

    pub(crate) fn root_descriptor(&self) -> &fs::File {
        &self.root
    }

    pub(crate) fn ensure_identity(&self, operation: &str) -> CoreResult<()> {
        descriptor::ensure_identity(self, operation)
    }

    /// Atomically publish a verified private staged body without following a
    /// root child or destination-parent link. Existing local content can only
    /// be replaced after a caller preserved its recovery copy.
    pub(crate) fn publish_staged_file(
        &self,
        staged: &Path,
        relative_destination: &Path,
        replace_existing: bool,
    ) -> CoreResult<()> {
        publication::publish_staged_file(self, staged, relative_destination, replace_existing)
    }

    /// Prepare a descriptor-bound private recovery copy without adding any
    /// scanner-visible name or hard link to the paired root. The caller may
    /// await one final remote witness before exchanging the staged and local
    /// inodes.
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_staged_file_replacement(
        &self,
        staged: &Path,
        relative_destination: &Path,
        expected_local: &shellx_drive_desktop_core::LocalEntry,
    ) -> CoreResult<Option<LinuxPreparedReplacement>> {
        mutation::prepare_staged_file_replacement(
            self,
            staged,
            relative_destination,
            expected_local,
        )
    }

    /// Publish a private staged file or tree only while its destination remains absent.
    pub(crate) fn publish_staged_entry_noreplace<F>(
        &self,
        staged: &Path,
        relative_destination: &Path,
        is_directory: bool,
        revalidate: F,
    ) -> CoreResult<()>
    where
        F: FnOnce() -> CoreResult<()>,
    {
        mutation::publish_staged_entry_noreplace(
            self,
            staged,
            relative_destination,
            is_directory,
            revalidate,
        )
    }

    /// Prepare a private macOS recovery copy without exposing any scratch
    /// entry to the scanner. Publication remains a separate, revalidated step.
    #[cfg(target_os = "macos")]
    pub(crate) fn prepare_staged_file_replacement(
        &self,
        staged: &Path,
        relative_destination: &Path,
        expected_local: &shellx_drive_desktop_core::LocalEntry,
    ) -> CoreResult<Option<MacOsPreparedReplacement>> {
        mutation::prepare_staged_file_replacement(
            self,
            staged,
            relative_destination,
            expected_local,
        )
    }

    /// Move an existing root-relative entry to an already-created absolute
    /// recovery destination.  The destination is always no-replace and the
    /// source/destination parents stay descriptor-bound.
    pub(crate) fn move_entry_to_recovery<F>(
        &self,
        relative_source: &Path,
        absolute_destination: &Path,
        is_directory: bool,
        revalidate: F,
    ) -> CoreResult<()>
    where
        F: FnOnce() -> CoreResult<()>,
    {
        mutation::move_entry_to_recovery(
            self,
            relative_source,
            absolute_destination,
            is_directory,
            revalidate,
        )
    }

    /// Rename one verified root-relative entry without replacing a destination.
    pub(crate) fn move_entry_noreplace<F>(
        &self,
        relative_source: &Path,
        relative_destination: &Path,
        is_directory: bool,
        revalidate: F,
    ) -> CoreResult<()>
    where
        F: FnOnce() -> CoreResult<()>,
    {
        mutation::move_entry_noreplace(
            self,
            relative_source,
            relative_destination,
            is_directory,
            revalidate,
        )
    }

    /// Move the complete paired root into an already-created private recovery
    /// batch. This is the implementation of explicit AccessRemoved removal;
    /// it never recursively deletes a user tree.
    pub(crate) fn move_complete_root_to_recovery<F>(
        &self,
        marker: &PairMarker,
        absolute_destination: &Path,
        revalidate: F,
    ) -> CoreResult<()>
    where
        F: FnOnce() -> CoreResult<()>,
    {
        mutation::move_complete_root_to_recovery(self, marker, absolute_destination, revalidate)
    }

    /// Create normal components under this exact selected root. Each existing
    /// component is reopened descriptor-relative with no link following.
    pub(crate) fn ensure_directory(&self, relative: &Path) -> CoreResult<()> {
        descriptor::ensure_directory(self, relative)
    }

    /// Create and bind a child root through this held base descriptor. A
    /// configured path may be checked later, but it never selects the inode
    /// that receives the first pairing marker.
    pub(crate) fn ensure_child_root(&self, relative: &Path) -> CoreResult<Self> {
        descriptor::ensure_child_root(self, relative)
    }

    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn ensure_empty_root(&self) -> CoreResult<()> {
        descriptor::ensure_empty_root(self)
    }

    /// Publish the first marker only while this child still names the inode
    /// opened under the selected base. A moved child loses its new marker.
    pub(crate) fn write_or_recognize_child_pair_marker(
        &self,
        relative: &Path,
        child: &Self,
        marker: &PairMarker,
    ) -> CoreResult<PairMarkerDisposition> {
        descriptor::write_or_recognize_child_pair_marker(self, relative, child, marker)
    }

    /// Create a mode-0600 private staging file below this exact descriptor
    /// root. The final name and every parent stay link-free and no-replace.
    pub(crate) fn create_private_staging_file(&self, relative: &Path) -> CoreResult<fs::File> {
        descriptor::create_private_staging_file(self, relative)
    }

    /// Open a tracked local source through the root descriptor, never through
    /// a later path resolution.
    pub(crate) fn open_regular_file(&self, relative: &Path) -> CoreResult<fs::File> {
        descriptor::open_regular_file(self, relative)
    }

    /// Read a current regular-file row through the pinned root descriptor.
    /// The caller compares it to a planned precondition immediately before a
    /// terminal local mutation.
    pub(crate) fn local_regular_entry(
        &self,
        relative: &Path,
    ) -> CoreResult<shellx_drive_desktop_core::LocalEntry> {
        descriptor::local_regular_entry(self, relative)
    }

    /// Check absence from a descriptor-open parent without following a leaf
    /// link. A present symlink, directory, device, or file is never treated as
    /// an available publication destination.
    pub(crate) fn local_entry_is_absent(&self, relative: &Path) -> CoreResult<bool> {
        descriptor::local_entry_is_absent(self, relative)
    }

    /// Conservatively reserve a Windows-compatible destination on a
    /// case-sensitive filesystem. The exact source may be excluded for a
    /// case-only rename; every other case alias stops publication.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn compatible_destination_is_absent(
        &self,
        relative: &Path,
        excluded_source: Option<&Path>,
    ) -> CoreResult<bool> {
        self.ensure_identity("compatible destination observation")?;
        let inspection = shellx_drive_desktop_core::inspect_local_tree(&self.path)?;
        self.ensure_identity("compatible destination observation")?;
        if !inspection.issues.is_empty() {
            return Ok(false);
        }
        Ok(inspection.entries.iter().all(|entry| {
            excluded_source == Some(entry.relative_path.as_path())
                || !windows_paths_equal_ignore_case(&entry.relative_path, relative)
        }))
    }

    /// Return a descriptor-observed directory identity. Empty relative paths
    /// name the selected root itself.
    pub(crate) fn local_directory_identity(
        &self,
        relative: &Path,
    ) -> CoreResult<DirectoryIdentity> {
        descriptor::local_directory_identity(self, relative)
    }

    /// Enrich a bounded planning scan with descriptor-observed identities.
    /// The shared scanner never invents directory identity from paths or bytes;
    /// Unix planners need the same native witness that their baseline retains.
    pub(crate) fn observe_directory_identities(
        &self,
        inspection: &mut shellx_drive_desktop_core::LocalTreeInspection,
        mut check: impl FnMut() -> CoreResult<()>,
    ) -> CoreResult<()> {
        for entry in inspection
            .entries
            .iter_mut()
            .filter(|entry| entry.is_directory)
        {
            check()?;
            entry.directory_identity = Some(self.local_directory_identity(&entry.relative_path)?);
        }
        Ok(())
    }

    /// Bind a non-secret pairing marker to this exact root through a private,
    /// no-follow temporary inode and non-replacing `linkat` publication.
    #[cfg(test)]
    pub(crate) fn write_or_recognize_pair_marker(
        &self,
        marker: &PairMarker,
    ) -> CoreResult<PairMarkerDisposition> {
        marker::write_or_recognize(self, marker)
    }

    pub(crate) fn require_exact_pair_marker(&self, marker: &PairMarker) -> CoreResult<()> {
        marker::require_exact(self, marker)
    }

    /// Remove only an exact, verified marker. User content is never removed.
    pub(crate) fn remove_exact_pair_marker(&self, marker: &PairMarker) -> CoreResult<bool> {
        marker::remove_exact(self, marker)
    }
}

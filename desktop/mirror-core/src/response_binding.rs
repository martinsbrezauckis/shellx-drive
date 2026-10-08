//! Exact request-to-response binding for server mutations.

use crate::{RemoteEntry, RemoteEntryKind, RemoteFile, RemoteFileKind};

pub fn created_remote_response_matches(
    file: &RemoteFile,
    expected_workspace_id: &str,
    expected_parent_id: Option<&str>,
    expected_name: &str,
    expected_kind: RemoteFileKind,
    expected_content_hash: Option<&str>,
) -> bool {
    !file.id.is_empty()
        && file.workspace_id == expected_workspace_id
        && file.parent_id.as_deref() == expected_parent_id
        && file.name == expected_name
        && file.kind == expected_kind
        && file.revision == 1
        && !file.trashed
        && file.content_hash.as_deref() == expected_content_hash
}

#[allow(clippy::too_many_arguments)]
pub fn updated_remote_response_matches(
    file: &RemoteFile,
    expected_id: &str,
    expected_workspace_id: &str,
    base_revision: i64,
    source: &RemoteEntry,
    expected_content_hash: Option<&str>,
    expected_size_bytes: u64,
) -> bool {
    mutation_identity_response_matches(
        file,
        expected_id,
        expected_workspace_id,
        base_revision,
        source,
        false,
    ) && expected_content_hash.is_some()
        && file.content_hash.as_deref() == expected_content_hash
        && content_size_response_matches(file, Some(expected_size_bytes))
}

pub fn trashed_remote_response_matches(
    file: &RemoteFile,
    expected_id: &str,
    expected_workspace_id: &str,
    base_revision: i64,
    source: &RemoteEntry,
) -> bool {
    mutation_identity_response_matches(
        file,
        expected_id,
        expected_workspace_id,
        base_revision,
        source,
        true,
    ) && file.content_hash == source.content_hash
        && content_size_response_matches(file, source.size_bytes)
}

pub fn restored_remote_response_matches(
    file: &RemoteFile,
    expected_id: &str,
    expected_workspace_id: &str,
    base_revision: i64,
    source: &RemoteEntry,
) -> bool {
    mutation_identity_response_matches(
        file,
        expected_id,
        expected_workspace_id,
        base_revision,
        source,
        false,
    ) && file.content_hash == source.content_hash
        && content_size_response_matches(file, source.size_bytes)
}

/// A PATCH response is accepted only when it proves the exact same Drive item
/// advanced one revision to the exact requested metadata path in the selected
/// workspace. The caller still refreshes the manifest before saving a baseline.
pub fn remote_move_response_matches(
    file: &RemoteFile,
    expected_id: &str,
    expected_workspace_id: &str,
    base_revision: i64,
    expected_parent_id: Option<&str>,
    expected_name: &str,
) -> bool {
    file.id == expected_id
        && file.workspace_id == expected_workspace_id
        && base_revision.checked_add(1) == Some(file.revision)
        && file.parent_id.as_deref() == expected_parent_id
        && file.name == expected_name
        && !file.trashed
}

fn content_size_response_matches(file: &RemoteFile, expected_size: Option<u64>) -> bool {
    file.size_bytes
        .map(u64::try_from)
        .transpose()
        .is_ok_and(|actual_size| actual_size == expected_size)
}

fn mutation_identity_response_matches(
    file: &RemoteFile,
    expected_id: &str,
    expected_workspace_id: &str,
    base_revision: i64,
    source: &RemoteEntry,
    expected_trashed: bool,
) -> bool {
    file.id == expected_id
        && file.workspace_id == expected_workspace_id
        && base_revision.checked_add(1) == Some(file.revision)
        && file.parent_id == source.parent_id
        && file.name == source.name
        && remote_kinds_match(&file.kind, &source.kind)
        && file.trashed == expected_trashed
}

fn remote_kinds_match(file: &RemoteFileKind, entry: &RemoteEntryKind) -> bool {
    matches!(
        (file, entry),
        (RemoteFileKind::File, RemoteEntryKind::File)
            | (RemoteFileKind::Folder, RemoteEntryKind::Folder)
    )
}

#[cfg(test)]
#[path = "response_binding_tests.rs"]
mod tests;

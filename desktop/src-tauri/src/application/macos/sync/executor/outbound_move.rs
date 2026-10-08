use std::{collections::BTreeMap, path::Path};

use shellx_drive_desktop_core::{
    map_remote_paths, remote_move_response_matches, windows_paths_equal_ignore_case,
    DriveHttpClient, FolderMovePrecondition, RemoteEntryKind, RemoteMoveTransfer,
    Result as CoreResult, SyncPair, SyncRoot,
};

use super::operations::ActionOutcome;
use super::{local, outbound::RemoteMoveInputs, outbound_witness, presentation, remote};

pub(super) async fn execute(input: RemoteMoveInputs<'_>) -> CoreResult<ActionOutcome> {
    let RemoteMoveInputs {
        guard,
        client,
        token,
        pair,
        root,
        remote_id,
        from,
        to,
        revision,
        folder,
    } = input;
    remote::require_pair_marker(guard, pair)?;
    remote::require_write_grant(root)?;
    let current = remote::fresh_writable_entries(client, token, root).await?;
    let Ok(paths) = map_remote_paths(&current, pair.remote_root_id.as_deref()) else {
        return Ok(stop(
            to,
            "Drive paths changed or collided before this rename.",
            folder,
        ));
    };
    let Some(source) = current
        .iter()
        .find(|entry| entry.id == remote_id && !entry.trashed && entry.revision == revision)
    else {
        return Ok(stop(
            to,
            "Drive changed or removed the tracked item before this rename.",
            folder,
        ));
    };
    if (source.kind == RemoteEntryKind::Folder) != folder.is_some() {
        return Ok(stop(
            to,
            "Drive changed the tracked item's kind before this rename.",
            folder,
        ));
    }
    if paths.get(remote_id).map(std::path::PathBuf::as_path) != Some(from) {
        return Ok(stop(
            to,
            "Drive changed the tracked item's path before this rename.",
            folder,
        ));
    }
    if !destination_is_available(&paths, remote_id, to) {
        return Ok(stop(
            to,
            "The Drive rename destination is occupied, including by a case-insensitive sibling alias.",
            folder,
        ));
    }
    let execution_folder = if let Some(folder) = folder {
        let Some(exact) = outbound_witness::capture(folder, remote_id, pair, &current) else {
            return Ok(stop(
                to,
                "Drive could not capture the complete folder subtree before this rename.",
                Some(folder),
            ));
        };
        Some(exact)
    } else {
        None
    };
    if !local::outbound_move_matches(guard, pair, to, source, execution_folder.as_ref())
        .unwrap_or(false)
    {
        return Ok(stop(
            to,
            "The local renamed source changed before Drive could apply it.",
            folder,
        ));
    }
    let folders = remote::folder_ids(&current, pair.remote_root_id.as_deref())?;
    let Ok(parent) = remote::parent(&folders, pair, to) else {
        return Ok(stop(to, "The Drive destination folder changed.", folder));
    };
    let Ok(name) = remote::leaf(to) else {
        return Ok(stop(to, "The Drive destination name is invalid.", folder));
    };
    remote::require_pair_marker(guard, pair)?;
    let moved = client
        .move_remote_file(token, remote_id, revision, parent.as_deref(), name)
        .await?;
    let moved = match moved {
        RemoteMoveTransfer::Moved(file)
            if remote_move_response_matches(
                &file,
                remote_id,
                &pair.workspace_id,
                revision,
                parent.as_deref(),
                name,
            ) =>
        {
            file
        }
        RemoteMoveTransfer::Conflict => {
            return Ok(stop(
                to,
                "Drive changed or atomically rejected an occupied rename destination.",
                folder,
            ));
        }
        RemoteMoveTransfer::NeedsReview | RemoteMoveTransfer::Moved(_) => {
            return Ok(stop(
                to,
                "Drive did not confirm the exact renamed item and destination.",
                folder,
            ));
        }
    };
    if !local::outbound_move_matches(guard, pair, to, source, execution_folder.as_ref())
        .unwrap_or(false)
    {
        return Ok(stop(
            to,
            "The local item changed while Drive completed its rename.",
            folder,
        ));
    }
    if !outbound_witness::terminal_matches(
        client,
        token,
        pair,
        root,
        source,
        &moved,
        to,
        execution_folder.as_ref(),
    )
    .await?
    {
        return Ok(stop(
            to,
            "Drive changed or collided after the rename response; no baseline was advanced.",
            folder,
        ));
    }
    Ok(ActionOutcome::Continue)
}

pub(super) fn destination_is_available(
    paths: &BTreeMap<String, std::path::PathBuf>,
    source_id: &str,
    destination: &Path,
) -> bool {
    paths
        .iter()
        .all(|(id, path)| id == source_id || !windows_paths_equal_ignore_case(path, destination))
}

fn stop(path: &Path, summary: &str, folder: Option<&FolderMovePrecondition>) -> ActionOutcome {
    ActionOutcome::Stop(presentation::move_review(
        path,
        summary,
        folder.is_some(),
        folder.map_or(0, |value| value.entries.len().saturating_sub(1)),
    ))
}

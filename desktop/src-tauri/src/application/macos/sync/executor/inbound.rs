//! Terminal actions that publish remote bytes into the local mirror.

use shellx_drive_desktop_core::{
    DesktopError, DownloadPrecondition, DriveHttpClient, RemoteEntry, RemoteEntryKind,
    Result as CoreResult, SyncAction, SyncPair, SyncRoot,
};

use super::operations::ActionOutcome;
use super::{inbound_move, transfer};

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    entries: &[RemoteEntry],
    action: &SyncAction,
) -> CoreResult<ActionOutcome> {
    match action {
        SyncAction::EnsureLocalDirectory { relative_path, .. } => {
            guard.ensure_directory(relative_path)?;
            Ok(ActionOutcome::Continue)
        }
        SyncAction::Download {
            remote_id,
            relative_path,
            revision,
            precondition,
        } => {
            let file = file(entries, remote_id, "download")?;
            if file.kind != RemoteEntryKind::File || file.revision != *revision {
                return Err(DesktopError::InvalidState(
                    "Drive download target changed before transfer".to_string(),
                ));
            }
            Ok(transfer::download(
                guard,
                client,
                token,
                pair,
                root,
                file,
                relative_path,
                relative_path,
                precondition,
            )
            .await?
            .map_or(ActionOutcome::Continue, ActionOutcome::Stop))
        }
        SyncAction::WriteRemoteConflictCopy {
            remote_id,
            local_path,
            conflict_path,
        } => {
            let file = file(entries, remote_id, "conflict")?;
            if file.kind != RemoteEntryKind::File {
                return Err(DesktopError::InvalidState(
                    "Drive conflict source is not a regular file".to_string(),
                ));
            }
            Ok(transfer::download(
                guard,
                client,
                token,
                pair,
                root,
                file,
                local_path,
                conflict_path,
                &DownloadPrecondition::Absent,
            )
            .await?
            .map_or(ActionOutcome::Continue, ActionOutcome::Stop))
        }
        SyncAction::MoveLocal {
            remote_id,
            from,
            to,
            precondition,
            folder_precondition,
        } => {
            inbound_move::execute(
                guard,
                client,
                token,
                pair,
                root,
                file(entries, remote_id, "local move")?,
                from,
                to,
                precondition,
                folder_precondition.as_ref(),
            )
            .await
        }
        _ => Err(DesktopError::InvalidState(
            "macOS inbound executor received an outbound action".to_string(),
        )),
    }
}

fn file<'a>(entries: &'a [RemoteEntry], id: &str, operation: &str) -> CoreResult<&'a RemoteEntry> {
    entries
        .iter()
        .find(|entry| entry.id == id && !entry.trashed)
        .ok_or_else(|| {
            DesktopError::InvalidState(format!(
                "Drive {operation} source disappeared before terminal mutation"
            ))
        })
}

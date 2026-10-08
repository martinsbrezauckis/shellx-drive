//! Terminal remote-move dispatch and routing for outbound actions.

use std::path::Path;

use shellx_drive_desktop_core::{
    DesktopError, DriveHttpClient, FolderMovePrecondition, Result as CoreResult, SyncAction,
    SyncPair, SyncRoot,
};

use super::operations::ActionOutcome;
use super::{outbound_move, upload};

/// Exact inputs for a revision-bound outbound rename.
pub(super) struct RemoteMoveInputs<'a> {
    pub(super) guard: &'a crate::platform::unix::filesystem::UnixRootGuard,
    pub(super) client: &'a DriveHttpClient,
    pub(super) token: &'a str,
    pub(super) pair: &'a SyncPair,
    pub(super) root: &'a SyncRoot,
    pub(super) remote_id: &'a str,
    pub(super) from: &'a Path,
    pub(super) to: &'a Path,
    pub(super) revision: i64,
    pub(super) folder: Option<&'a FolderMovePrecondition>,
}

pub(super) async fn execute(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    action: &SyncAction,
) -> CoreResult<ActionOutcome> {
    match action {
        SyncAction::UploadNew {
            relative_path,
            is_directory,
            local,
        } => {
            upload::new(
                guard,
                client,
                token,
                pair,
                root,
                relative_path,
                *is_directory,
                local,
            )
            .await
        }
        SyncAction::UploadExisting {
            remote_id,
            relative_path,
            base_revision,
            local,
        } => {
            upload::existing(
                guard,
                client,
                token,
                pair,
                root,
                remote_id,
                relative_path,
                *base_revision,
                local,
            )
            .await
        }
        SyncAction::MoveRemote {
            remote_id,
            from,
            to,
            base_revision,
            folder_precondition,
        } => {
            outbound_move::execute(RemoteMoveInputs {
                guard,
                client,
                token,
                pair,
                root,
                remote_id,
                from,
                to,
                revision: *base_revision,
                folder: folder_precondition.as_ref(),
            })
            .await
        }
        _ => Err(DesktopError::InvalidState(
            "macOS outbound executor received an inbound action".to_string(),
        )),
    }
}

//! Ordered terminal action dispatch for macOS reconciliation.

use std::path::Path;

use shellx_drive_desktop_core::{
    DesktopError, DriveHttpClient, RemoteEntry, Result as CoreResult, ReviewItem, SyncAction,
    SyncPair, SyncRoot, SyncRun,
};

use super::{inbound, outbound};

pub(super) enum ActionOutcome {
    Continue,
    Review(ReviewItem),
    Stop(ReviewItem),
}

// Keep cancellation and filesystem authority explicit at the dispatch boundary.
#[allow(clippy::too_many_arguments)]
pub(in crate::application::macos::sync) async fn execute_actions(
    run: &SyncRun,
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    sync_root: &SyncRoot,
    remote: &[RemoteEntry],
    actions: &[SyncAction],
) -> CoreResult<Vec<ReviewItem>> {
    let mut ordered = actions.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|action| {
        (
            action_rank(action),
            action_path(action).components().count(),
        )
    });
    let mut reviews = Vec::new();
    for action in ordered {
        run.ensure_not_cancelled()?;
        let outcome = match action {
            SyncAction::EnsureLocalDirectory { .. }
            | SyncAction::Download { .. }
            | SyncAction::MoveLocal { .. }
            | SyncAction::WriteRemoteConflictCopy { .. } => {
                inbound::execute(guard, client, token, pair, sync_root, remote, action).await?
            }
            SyncAction::UploadNew { .. }
            | SyncAction::UploadExisting { .. }
            | SyncAction::MoveRemote { .. } => {
                outbound::execute(guard, client, token, pair, sync_root, action).await?
            }
        };
        match outcome {
            ActionOutcome::Continue => {}
            ActionOutcome::Review(review) => reviews.push(review),
            ActionOutcome::Stop(review) => {
                reviews.push(review);
                break;
            }
        }
        run.ensure_not_cancelled()?;
    }
    Ok(reviews)
}

fn action_rank(action: &SyncAction) -> u8 {
    match action {
        SyncAction::EnsureLocalDirectory { .. } => 0,
        SyncAction::MoveLocal { .. } => 1,
        SyncAction::Download { .. } => 2,
        SyncAction::UploadNew {
            is_directory: true, ..
        } => 3,
        SyncAction::UploadNew { .. } => 4,
        SyncAction::UploadExisting { .. } | SyncAction::MoveRemote { .. } => 5,
        SyncAction::WriteRemoteConflictCopy { .. } => 6,
    }
}

fn action_path(action: &SyncAction) -> &Path {
    match action {
        SyncAction::EnsureLocalDirectory { relative_path, .. }
        | SyncAction::Download { relative_path, .. }
        | SyncAction::UploadNew { relative_path, .. }
        | SyncAction::UploadExisting { relative_path, .. } => relative_path,
        SyncAction::MoveLocal { to, .. } | SyncAction::MoveRemote { to, .. } => to,
        SyncAction::WriteRemoteConflictCopy { conflict_path, .. } => conflict_path,
    }
}

#[cfg(test)]
mod tests {
    use super::action_rank;
    use shellx_drive_desktop_core::{DownloadPrecondition, SyncAction};
    use std::path::PathBuf;

    #[test]
    fn macos_orders_moves_and_conflict_copies_after_dependencies() {
        let local_move = SyncAction::MoveLocal {
            remote_id: "id".to_string(),
            from: PathBuf::from("old"),
            to: PathBuf::from("new"),
            precondition: DownloadPrecondition::Absent,
            folder_precondition: None,
        };
        let conflict_copy = SyncAction::WriteRemoteConflictCopy {
            remote_id: "id".to_string(),
            local_path: PathBuf::from("local"),
            conflict_path: PathBuf::from("conflict"),
        };
        assert_eq!(action_rank(&local_move), 1);
        assert_eq!(action_rank(&conflict_copy), 6);
    }
}

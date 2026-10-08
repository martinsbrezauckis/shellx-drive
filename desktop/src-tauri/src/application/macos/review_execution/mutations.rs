//! Revision-bound mutations for confirmed macOS review decisions.

use shellx_drive_desktop_core::{
    map_remote_paths, restored_remote_response_matches, trashed_remote_response_matches,
    DesktopError, DriveHttpClient, RemoteEntry, Result as CoreResult, ReviewDecision, ReviewItem,
};

use super::{recovery, restore};

/// The immutable, exact review witnesses used by one confirmed mutation.
pub(super) struct ConfirmedReviewInputs<'a> {
    pub(super) guard: &'a crate::platform::unix::filesystem::UnixRootGuard,
    pub(super) client: &'a DriveHttpClient,
    pub(super) token: &'a str,
    pub(super) pair: &'a shellx_drive_desktop_core::SyncPair,
    pub(super) state: &'a shellx_drive_desktop_core::DesktopState,
    pub(super) item: &'a ReviewItem,
    pub(super) remote: &'a [RemoteEntry],
    pub(super) budget: &'a mut shellx_drive_desktop_core::SyncCycleBudget,
}

pub(super) async fn execute_decision(
    input: ConfirmedReviewInputs<'_>,
    decision: ReviewDecision,
) -> CoreResult<()> {
    let ConfirmedReviewInputs {
        guard,
        client,
        token,
        pair,
        state,
        item,
        remote,
        budget,
    } = input;
    let baseline = state
        .baseline
        .values()
        .find(|entry| entry.relative_path == item.relative_path)
        .ok_or_else(|| {
            DesktopError::InvalidState("the review has no matching saved baseline".to_string())
        })?;
    match decision {
        ReviewDecision::TrashRemote => {
            trash_remote(guard, client, token, pair, state, item, baseline, remote).await
        }
        ReviewDecision::RestoreLocal => {
            restore::restore_local(guard, client, token, pair, state, item, remote, budget).await
        }
        ReviewDecision::RestoreRemote => {
            restore_remote(guard, client, token, pair, state, baseline, remote).await
        }
        ReviewDecision::RecoverLocal => {
            recovery::recover_local(pair, state, item, guard, remote).map(|_| ())
        }
        ReviewDecision::RemoveRetainedRoot => Err(DesktopError::InvalidState(
            "retained-root recovery must run through the local-only review path".to_string(),
        )),
    }
}

async fn trash_remote(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &shellx_drive_desktop_core::SyncPair,
    state: &shellx_drive_desktop_core::DesktopState,
    item: &ReviewItem,
    baseline: &shellx_drive_desktop_core::BaselineEntry,
    remote: &[RemoteEntry],
) -> CoreResult<()> {
    require_writer(state, pair)?;
    if item.is_directory {
        return Err(DesktopError::InvalidState(
            "macOS does not trash reviewed folders without a complete current subtree witness"
                .to_string(),
        ));
    }
    let current = remote
        .iter()
        .find(|entry| entry.id == baseline.remote_id && !entry.trashed)
        .ok_or_else(|| {
            DesktopError::InvalidState("Drive item changed before it could be trashed".to_string())
        })?;
    if current.revision != baseline.revision {
        return Err(DesktopError::InvalidState(
            "Drive item changed after review; no remote deletion was sent".to_string(),
        ));
    }
    require_terminal_pair(guard, pair)?;
    let trashed = client.trash_file(token, &baseline.remote_id).await?;
    if !trashed_remote_response_matches(
        &trashed,
        &baseline.remote_id,
        &pair.workspace_id,
        current.revision,
        current,
    ) {
        return Err(DesktopError::InvalidState(
            "Drive did not return the exact trashed file and next revision; the review remains pending"
                .to_string(),
        ));
    }
    Ok(())
}

async fn restore_remote(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &shellx_drive_desktop_core::SyncPair,
    state: &shellx_drive_desktop_core::DesktopState,
    baseline: &shellx_drive_desktop_core::BaselineEntry,
    remote: &[RemoteEntry],
) -> CoreResult<()> {
    require_writer(state, pair)?;
    let current = remote
        .iter()
        .find(|entry| entry.id == baseline.remote_id && entry.trashed)
        .ok_or_else(|| {
            DesktopError::InvalidState("Drive no longer has the reviewed trashed item".to_string())
        })?;
    if map_remote_paths(remote, pair.remote_root_id.as_deref())?
        .values()
        .any(|path| path == &baseline.relative_path)
    {
        return Err(DesktopError::InvalidState(
            "another live Drive item now occupies this restore path; no overwrite was attempted"
                .to_string(),
        ));
    }
    require_terminal_pair(guard, pair)?;
    let restored = client.restore_file(token, &baseline.remote_id).await?;
    if !restored_remote_response_matches(
        &restored,
        &baseline.remote_id,
        &pair.workspace_id,
        current.revision,
        current,
    ) {
        return Err(DesktopError::InvalidState(
            "Drive did not return the exact restored file and next revision; the review remains pending"
                .to_string(),
        ));
    }
    Ok(())
}

fn require_writer(
    state: &shellx_drive_desktop_core::DesktopState,
    pair: &shellx_drive_desktop_core::SyncPair,
) -> CoreResult<()> {
    if state
        .sync_root_for_pair(pair)
        .is_some_and(|metadata| metadata.root.role.may_write())
    {
        Ok(())
    } else {
        Err(DesktopError::InvalidState(
            "Viewer access cannot change Drive through a review action".to_string(),
        ))
    }
}

fn require_terminal_pair(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    pair: &shellx_drive_desktop_core::SyncPair,
) -> CoreResult<()> {
    guard.ensure_identity("paired-root review mutation boundary")?;
    guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(pair))
}

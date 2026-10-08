//! Mutations for a review after authority has been independently rechecked.

use super::super::*;

pub(super) struct Inputs<'a> {
    pub(super) client: &'a DriveHttpClient,
    pub(super) token: &'a str,
    pub(super) pair: &'a SyncPair,
    pub(super) state: &'a DesktopState,
    pub(super) item: &'a ReviewItem,
    pub(super) baseline: &'a BaselineEntry,
    pub(super) remote: &'a [RemoteEntry],
    pub(super) cycle_budget: &'a mut SyncCycleBudget,
}

pub(super) async fn execute(
    Inputs {
        client,
        token,
        pair,
        state,
        item,
        baseline,
        remote,
        cycle_budget,
    }: Inputs<'_>,
    decision: ReviewDecision,
) -> CoreResult<()> {
    match decision {
        ReviewDecision::TrashRemote => {
            if baseline.kind.eq_ignore_ascii_case("folder") {
                return Err(DesktopError::InvalidState(
                    "Drive folder trash stays disabled until the server provides a conditional recursive delete".to_string(),
                ));
            }
            reviewed_remote_subtree_matches_baseline(
                item,
                &state.baseline,
                pair.remote_root_id.as_deref(),
                remote,
            )?;
            let current = current_baseline_remote(remote, baseline)?;
            cycle_budget.admit_extra(0, 0, 0, 1)?;
            let trashed = with_current_pair_remote_mutation(state, pair, || async {
                client.trash_file(token, &baseline.remote_id).await
            })
            .await?;
            if !trashed_remote_response_matches(
                &trashed,
                &baseline.remote_id,
                &pair.workspace_id,
                current.revision,
                current,
            ) {
                return Err(DesktopError::InvalidState(
                    "Drive did not return the exact trashed file and next revision; the review remains pending".to_string(),
                ));
            }
        }
        ReviewDecision::RestoreLocal => {
            restore_local_tree(client, token, pair, state, item, remote, cycle_budget).await?
        }
        ReviewDecision::RecoverLocal => {
            if remote
                .iter()
                .any(|entry| entry.id == baseline.remote_id && !entry.trashed)
            {
                return Err(DesktopError::InvalidState(
                    "Drive restored this item after the review; the local copy was left in place"
                        .to_string(),
                ));
            }
            move_local_to_recovery(pair, state, item)?;
        }
        ReviewDecision::RestoreRemote => {
            if remote
                .iter()
                .any(|entry| entry.id == baseline.remote_id && !entry.trashed)
            {
                return Err(DesktopError::InvalidState(
                    "Drive already restored this item; no overwrite was attempted".to_string(),
                ));
            }
            let paths = map_remote_paths(remote, pair.remote_root_id.as_deref())?;
            if paths.values().any(|path| path == &baseline.relative_path) {
                return Err(DesktopError::InvalidState(
                    "another live Drive item now occupies this restore path; no overwrite was attempted".to_string(),
                ));
            }
            let current = remote
                .iter()
                .find(|entry| entry.id == baseline.remote_id && entry.trashed)
                .ok_or_else(|| {
                    DesktopError::InvalidState(
                        "Drive no longer has the reviewed trashed item; no restore was attempted"
                            .to_string(),
                    )
                })?;
            cycle_budget.admit_extra(0, 0, 0, 1)?;
            let restored = with_current_pair_remote_mutation(state, pair, || async {
                client.restore_file(token, &baseline.remote_id).await
            })
            .await?;
            if !restored_remote_response_matches(
                &restored,
                &baseline.remote_id,
                &pair.workspace_id,
                current.revision,
                current,
            ) {
                return Err(DesktopError::InvalidState(
                    "Drive did not return the exact restored file and next revision; the review remains pending".to_string(),
                ));
            }
        }
        ReviewDecision::RemoveRetainedRoot => unreachable!("handled before Drive access"),
    }
    Ok(())
}

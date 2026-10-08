//! Bounded candidate admission that retains exact local-slot ownership.

use chrono::{DateTime, Utc};
use shellx_drive_desktop_core::{
    DesktopError, DesktopState, RemoteSessionRecord, Result as CoreResult,
    MAX_PENDING_REMOTE_REVOCATIONS,
};

/// Check before issuing a fresh session. An expired remote locator can still
/// own a retained staged credential; capacity admission must never evict it.
pub(crate) fn ensure_candidate_admission(state: &DesktopState) -> CoreResult<()> {
    let extra = state
        .pending_candidate_session
        .as_ref()
        .is_some_and(|prior| {
            !state
                .pending_remote_revocations
                .iter()
                .any(|record| record.same_remote_session(prior))
        });
    require_capacity(state.pending_remote_revocations.len() + usize::from(extra))
}

/// Prepare the new locator without expiry pruning. Older locators are removed
/// only by exact remote retirement and confirmed local deletion. The existing
/// typed records and state limits remain the durable format.
pub(crate) fn prepare_candidate_state(
    state: &DesktopState,
    current: &RemoteSessionRecord,
    now: DateTime<Utc>,
) -> CoreResult<DesktopState> {
    if current.expires_at <= now {
        return Err(DesktopError::Credential(
            "Drive returned an expired sign-in session".to_string(),
        ));
    }
    let mut prepared = state.clone();
    prepared
        .pending_remote_revocations
        .retain(|record| !record.same_remote_session(current));
    if let Some(prior) = state.pending_candidate_session.as_ref() {
        if !prior.same_remote_session(current)
            && !prepared
                .pending_remote_revocations
                .iter()
                .any(|record| record.same_remote_session(prior))
        {
            prepared.pending_remote_revocations.push(prior.clone());
        }
    }
    require_capacity(prepared.pending_remote_revocations.len())?;
    prepared.pending_remote_revocations.sort_by(|left, right| {
        left.expires_at
            .cmp(&right.expires_at)
            .then_with(|| left.server_url.cmp(&right.server_url))
            .then_with(|| left.account_email.cmp(&right.account_email))
            .then_with(|| left.session_id.cmp(&right.session_id))
    });
    prepared.pending_candidate_session = Some(current.clone());
    Ok(prepared)
}

fn require_capacity(count: usize) -> CoreResult<()> {
    if count > MAX_PENDING_REMOTE_REVOCATIONS {
        return Err(DesktopError::Credential(
            "Drive credential recovery must retire retained sessions before another sign-in"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

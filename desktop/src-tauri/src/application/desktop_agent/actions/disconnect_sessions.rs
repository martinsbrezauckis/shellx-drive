//! Exact same-owner session retirement before agent capability retirement.

use shellx_drive_desktop_core::{DesktopError, Result as CoreResult};

use super::super::Runtime;

/// Derive the exact current session locator before any agent Disconnect
/// mutation. A legacy bearer without this locator fails closed because the
/// capability route may retire only its device-bound session.
pub(in crate::application::desktop_agent) fn bound_agent_owner_session(
    runtime: &Runtime,
) -> CoreResult<shellx_drive_desktop_core::RemoteSessionRecord> {
    use shellx_drive_desktop_core::RemoteSessionRecord;

    let session = runtime.current_session()?;
    let bearer = runtime.current_token(&session)?;
    RemoteSessionRecord::from_local_bearer(&session.server_url, &session.email, &bearer)
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "desktop-agent Disconnect needs a current session locator before retiring prior sessions"
                    .to_string(),
            )
        })
}

/// Retire only the exact same-owner sessions that are not the session bound to
/// this broker device. Each accepted receipt is persisted before the next
/// request, so this routine may repeat after a crash without widening scope.
pub(in crate::application::desktop_agent) async fn retire_non_bound_agent_sessions(
    runtime: &Runtime,
    bound_owner_session: &shellx_drive_desktop_core::RemoteSessionRecord,
) -> CoreResult<()> {
    use shellx_drive_desktop_core::RemoteSessionRevocationOutcome;

    let session = runtime.current_session()?;
    let bearer = runtime.current_token(&session)?;
    let current = bound_agent_owner_session(runtime)?;
    if current.session_id != bound_owner_session.session_id {
        return Err(DesktopError::InvalidState(
            "desktop-agent Disconnect current session changed before remote retirement".to_string(),
        ));
    }
    let records = {
        let state = runtime.coordinator.snapshot();
        let mut records = state
            .pending_remote_revocations
            .iter()
            .chain(state.pending_candidate_session.iter())
            .chain(state.active_remote_session.iter())
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        records.dedup_by(|left, right| left.session_id == right.session_id);
        records
    };
    let client = shellx_drive_desktop_core::DriveHttpClient::new(&session.server_url)?;
    for record in records {
        if !record.identity_matches(&session.server_url, &session.email) {
            return Err(DesktopError::InvalidState(
                "desktop-agent Disconnect cannot retire a session from another server or account"
                    .to_string(),
            ));
        }
        if record.session_id == bound_owner_session.session_id {
            continue;
        }
        match client.revoke_session(&bearer, &record.session_id).await? {
            RemoteSessionRevocationOutcome::Revoked
            | RemoteSessionRevocationOutcome::AlreadyAbsent => {
                super::super::update_desktop_state(runtime, |state| {
                    state.remove_remote_session_record(&record);
                    Ok(())
                })?;
            }
        }
    }
    Ok(())
}

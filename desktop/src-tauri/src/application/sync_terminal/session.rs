//! Exact saved-session rejection after an authenticated Drive 401.

use shellx_drive_desktop_core::{DesktopError, Result as CoreResult, SyncRun};

use crate::{application::Runtime, session_identity::SessionIdentity};

pub(crate) fn is_user_session_unauthorized(error: &DesktopError) -> bool {
    matches!(error, DesktopError::Server { status: 401, .. })
}

/// Project a Drive 401 through session admission. Only the exact captured
/// bearer is removed; a stale rejection instead leaves the current session view intact.
pub(crate) async fn admit_user_session_response<T>(
    runtime: &Runtime,
    session: &SessionIdentity,
    captured_bearer: &str,
    result: CoreResult<T>,
) -> CoreResult<T> {
    let error = match result {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    if !is_user_session_unauthorized(&error) {
        return Err(error);
    }
    // A changed or already-absent bearer means this response is stale. It
    // must not turn a newer session into a persisted terminal error.
    runtime
        .invalidate_captured_pair_credential(session, captured_bearer)
        .await?;
    Err(DesktopError::NeedsReconnect)
}

/// Same 401 admission while a caller already holds `auth_publication` across
/// its captured authority request. This must remain synchronous so initial
/// pairing can retire an exact rejected bearer without trying to lock it again.
pub(crate) fn admit_user_session_response_during_publication<T>(
    runtime: &Runtime,
    session: &SessionIdentity,
    captured_bearer: &str,
    result: CoreResult<T>,
) -> CoreResult<T> {
    let error = match result {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    if !is_user_session_unauthorized(&error) {
        return Err(error);
    }
    runtime.invalidate_captured_pair_credential_during_publication(session, captured_bearer)?;
    Err(DesktopError::NeedsReconnect)
}

/// Persist completed roots, then retain the reservation through credential
/// admission so a late 401 cannot race a second operation into Error.
pub(crate) async fn admit_persisted_all_roots(
    runtime: &Runtime,
    run: &mut SyncRun,
    selected_pair_id: &str,
    session: &SessionIdentity,
    captured_bearer: &str,
    rejected: DesktopError,
) -> CoreResult<()> {
    let final_state = run.finalize_all_roots_state(selected_pair_id)?;
    runtime.store.save(&final_state)?;
    let result =
        admit_user_session_response(runtime, session, captured_bearer, Err(rejected)).await;
    run.finish_persisted_state(final_state, |state| runtime.store.save(state))?;
    result
}

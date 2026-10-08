//! Serialized recovery for candidate slots left by interrupted publication.

#[path = "candidate_startup_recovery/reconcile.rs"]
mod reconcile;

use super::*;
use reconcile::recover_staged_candidates;

pub(super) fn recovery_error() -> DesktopError {
    DesktopError::Credential(
        "Drive credential recovery needs retry; credentials were kept for retry".to_string(),
    )
}

/// Run before the first poller starts. The auth and lifecycle guards make this
/// a single recovery authority relative to login, disconnect, pairing, and
/// sync state publication.
pub(super) fn recover_staged_candidates_before_polling(runtime: &Runtime) -> CoreResult<()> {
    let result = tauri::async_runtime::block_on(async {
        let _auth_publication = runtime.auth_publication.lock().await;
        let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
        let mut state = runtime.coordinator.snapshot();
        let mut result = recover_staged_candidates(runtime, &mut state).await;
        if result.is_ok() {
            // Do not erase an unrelated user-visible failure merely because
            // candidate recovery converged. This exact message is written by
            // app startup when this recovery previously paused polling.
            let mut recovered = state.clone();
            if recovered.clear_candidate_recovery_error() {
                match runtime.store.save(&recovered) {
                    Ok(()) => state = recovered,
                    Err(error) => result = Err(error),
                }
            }
        }
        operation.finish_state(state);
        result
    });
    runtime.set_candidate_recovery_pending(result.is_err());
    result
}

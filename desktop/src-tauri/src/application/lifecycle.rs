//! Platform-neutral lifecycle state transitions.

use shellx_drive_desktop_core::Result as CoreResult;

use super::Runtime;

/// The native shell decides how to repaint its tray after this transition;
/// persistence itself has no Windows-specific behavior.
pub(crate) async fn persist_paused_state(runtime: &Runtime, paused: bool) -> CoreResult<()> {
    let _auth_publication = runtime.auth_publication.lock().await;
    persist_paused_state_after_publication(runtime, paused)
}

pub(crate) async fn toggle_paused_state(runtime: &Runtime) -> CoreResult<()> {
    let _auth_publication = runtime.auth_publication.lock().await;
    let paused = !runtime.coordinator.snapshot().paused;
    persist_paused_state_after_publication(runtime, paused)
}

fn persist_paused_state_after_publication(runtime: &Runtime, paused: bool) -> CoreResult<()> {
    // A Disconnect journal is the exact authority for the retained local
    // tree. Do not publish any other lifecycle state while that cleanup is
    // unfinished, even a pause preference.
    runtime.ensure_disconnect_cleanup_complete()?;
    let mut operation = runtime.coordinator.begin_lifecycle_operation()?;
    let mut candidate = runtime.coordinator.snapshot();
    candidate.set_all_pairs_paused(paused);
    runtime.store.save(&candidate)?;
    operation.finish_state(candidate);
    Ok(())
}

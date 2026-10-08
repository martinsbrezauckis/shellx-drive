//! Exact local Disconnect cleanup steps and durable acknowledgements.

use super::*;

pub(crate) const DISCONNECT_CLEANUP_PENDING_ERROR: &str =
    "Disconnect local cleanup remains pending; retry Disconnect to complete it.";

/// Resume only a cleanup whose disconnected projection was already durable.
/// A retained pair means remote retirement did not reach its commit point, so
/// local marker and credential deletion remain prohibited.
pub(crate) fn resume_disconnected_local_cleanup(
    store: &StateStore,
    state: &mut DesktopState,
) -> CoreResult<()> {
    if state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
        && state.pair.is_none()
    {
        complete_pending_local_cleanup(store, state)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) fn persist_disconnect_cleanup_intent(
    runtime: &Runtime,
    state: &mut DesktopState,
) -> CoreResult<()> {
    if state.has_pending_disconnect_cleanup() {
        return Ok(());
    }
    let intent = DisconnectCleanupIntent::for_disconnect_pairs(
        state.pairs().cloned().collect(),
        WindowsCredentialStore::disconnect_credential_slots()?,
    )?;
    let mut next = state.clone();
    next.begin_disconnect_cleanup(intent)?;
    runtime.store.save(&next)?;
    *state = next;
    Ok(())
}

/// Save progress only after the exact local side effect succeeded. The working
/// state is cloned first, so a failed save leaves the in-memory retry journal
/// intact as well as the durable one.
fn save_cleanup_progress(
    store: &StateStore,
    state: &mut DesktopState,
    advance: impl FnOnce(&mut DisconnectCleanupIntent) -> CoreResult<()>,
) -> CoreResult<()> {
    let mut next = state.clone();
    advance(next.pending_disconnect_cleanup_mut().ok_or_else(|| {
        DesktopError::InvalidState("disconnect cleanup was not pending".to_string())
    })?)?;
    store.save(&next)?;
    *state = next;
    Ok(())
}

/// Delete exact local items with independently persisted acknowledgements.
pub(crate) fn complete_pending_local_cleanup(
    store: &StateStore,
    state: &mut DesktopState,
) -> CoreResult<()> {
    complete_local_cleanup_with_finalizer(store, state, DesktopState::finish_disconnect_cleanup)
}

pub(crate) fn complete_local_cleanup_with_finalizer(
    store: &StateStore,
    state: &mut DesktopState,
    finalize: impl FnOnce(&mut DesktopState) -> CoreResult<()>,
) -> CoreResult<()> {
    if !state
        .pending_disconnect_cleanup()
        .is_some_and(DisconnectCleanupIntent::remote_retirement_confirmed)
    {
        return Err(DesktopError::InvalidState(
            "disconnect local cleanup cannot run before remote retirement is confirmed".to_string(),
        ));
    }
    while let Some(marker) = state
        .pending_disconnect_cleanup()
        .and_then(|cleanup| cleanup.marker.clone())
    {
        let _root_guard =
            pair_root_identity::guard_disconnected_pair_root(&marker.local_root, &marker.marker)?;
        pair_marker::remove(&marker.local_root, &marker.marker)?;
        save_cleanup_progress(store, state, |cleanup| {
            cleanup.acknowledge_marker();
            Ok(())
        })?;
    }

    while let Some(slot) = state
        .pending_disconnect_cleanup()
        .and_then(|cleanup| cleanup.next_credential_slot().cloned())
    {
        WindowsCredentialStore::delete_and_verify_disconnect_credential_slot(&slot)?;
        save_cleanup_progress(store, state, |cleanup| {
            cleanup.acknowledge_credential_slot(&slot)
        })?;
    }

    if state.has_pending_disconnect_cleanup() {
        let mut next = state.clone();
        finalize(&mut next)?;
        if next.last_error.as_deref() == Some(DISCONNECT_CLEANUP_PENDING_ERROR) {
            next.last_error = None;
        }
        store.save(&next)?;
        *state = next;
    }
    Ok(())
}

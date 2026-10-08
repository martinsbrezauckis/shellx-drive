//! Serialized lifecycle and sync-run coordination around the pure mirror planner.

mod disconnect;
mod pair_management;
mod sync_run;

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::{
    sync_pair_id, ActivityEntry, DesktopAgentControlState, DesktopError, DesktopState, Result,
    SyncStatus,
};

pub use disconnect::DisconnectRequest;

pub(super) struct CoordinatorInner {
    state: DesktopState,
    active_run: bool,
    active_sync_generation: Option<u64>,
    next_sync_generation: u64,
    disconnect_request: Option<u64>,
    next_disconnect_request: u64,
    sync_cancellation: Option<(u64, u64)>,
    offline: bool,
}

/// One coherent coordinator image for a browser-facing runtime projection.
/// Credential availability is deliberately resolved after this image is cloned,
/// so platform credential I/O never occurs while holding the coordinator lock.
#[derive(Clone)]
pub struct CoordinatorViewSnapshot {
    pub state: DesktopState,
    pub active_run: bool,
    pub disconnect_requested: bool,
    pub offline: bool,
}

/// Small serialized control plane around the pure reconciliation planner. A
/// filesystem watcher and Drive poller must both acquire this guard, so they
/// cannot race one pair into two concurrent passes.
#[derive(Clone)]
pub struct MirrorCoordinator {
    pub(super) inner: Arc<Mutex<CoordinatorInner>>,
}

impl MirrorCoordinator {
    pub fn new(state: DesktopState) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CoordinatorInner {
                state,
                active_run: false,
                active_sync_generation: None,
                next_sync_generation: 0,
                disconnect_request: None,
                next_disconnect_request: 0,
                sync_cancellation: None,
                offline: false,
            })),
        }
    }

    pub fn snapshot(&self) -> DesktopState {
        self.view_snapshot().state
    }

    pub fn view_snapshot(&self) -> CoordinatorViewSnapshot {
        let inner = self.inner.lock().expect("mirror coordinator lock");
        CoordinatorViewSnapshot {
            state: inner.state.clone(),
            active_run: inner.active_run,
            disconnect_requested: inner.disconnect_request.is_some(),
            offline: inner.offline,
        }
    }

    pub fn status(&self, credential_available: bool) -> SyncStatus {
        let inner = self.inner.lock().expect("mirror coordinator lock");
        inner
            .state
            .status(inner.active_run, inner.offline, credential_available)
    }

    pub fn begin_run(&self) -> Result<SyncRun> {
        let mut inner = self.inner.lock().expect("mirror coordinator lock");
        if inner.active_run || inner.disconnect_request.is_some() {
            return Err(DesktopError::SyncAlreadyRunning);
        }
        if inner.state.has_pending_disconnect_cleanup() {
            return Err(DesktopError::InvalidState(
                "disconnect local cleanup is pending; sync remains disabled".to_string(),
            ));
        }
        if inner.state.pair.is_none() {
            return Err(DesktopError::NeedsSetup);
        }
        if inner.state.paused {
            return Err(DesktopError::SyncPaused);
        }
        let state = inner.state.clone();
        // Display selection and per-root activation reshuffle the detached
        // state. Fairness must use the same order across runs and restarts.
        let mut cycle_order: Vec<String> = state.pairs().map(sync_pair_id).collect();
        cycle_order.sort_unstable();
        inner.next_sync_generation =
            inner.next_sync_generation.checked_add(1).ok_or_else(|| {
                DesktopError::InvalidState("sync-run generation overflowed".to_string())
            })?;
        let generation = inner.next_sync_generation;
        inner.active_run = true;
        inner.active_sync_generation = Some(generation);
        Ok(SyncRun {
            coordinator: self.clone(),
            state,
            cycle_order,
            active: true,
            generation,
        })
    }

    pub fn set_launch_at_login(&self, enabled: bool) {
        self.inner
            .lock()
            .expect("mirror coordinator lock")
            .state
            .launch_at_login = enabled;
    }

    pub fn append_activity(&self, entry: ActivityEntry) {
        self.inner
            .lock()
            .expect("mirror coordinator lock")
            .state
            .append_activity(entry);
    }

    pub fn disconnect(&self) -> Result<()> {
        let mut operation = self.begin_lifecycle_operation()?;
        operation.finish_disconnect();
        Ok(())
    }

    /// Reserve a lifecycle operation such as disconnect or role discovery so
    /// it cannot race an active sync, selection, or re-pair.
    pub fn begin_lifecycle_operation(&self) -> Result<LifecycleOperation> {
        let mut inner = self.inner.lock().expect("mirror coordinator lock");
        if inner.active_run || inner.disconnect_request.is_some() {
            return Err(DesktopError::SyncAlreadyRunning);
        }
        inner.active_run = true;
        Ok(LifecycleOperation {
            coordinator: self.clone(),
            active: true,
        })
    }

    /// Update only the durable desktop-agent journal while a detached sync
    /// snapshot is active. Persistence completes before the live image changes;
    /// sync terminal publication preserves this field instead of overwriting it.
    pub fn update_desktop_agent_control<T>(
        &self,
        update: impl FnOnce(&mut DesktopAgentControlState) -> Result<T>,
        persist: impl FnOnce(&DesktopState) -> Result<()>,
    ) -> Result<T> {
        let mut inner = self.inner.lock().expect("mirror coordinator lock");
        if inner.active_run && inner.active_sync_generation.is_none() {
            return Err(DesktopError::SyncAlreadyRunning);
        }
        let mut next = inner.state.clone();
        let value = update(&mut next.desktop_agent_control)?;
        persist(&next)?;
        inner.state = next;
        Ok(value)
    }

    pub fn set_offline(&self, offline: bool) {
        self.inner.lock().expect("mirror coordinator lock").offline = offline;
    }

    pub fn record_error(&self, message: impl Into<String>) {
        let mut inner = self.inner.lock().expect("mirror coordinator lock");
        inner.state.last_error = Some(redact_error(&message.into()));
    }

    pub fn clear_error(&self) {
        self.inner
            .lock()
            .expect("mirror coordinator lock")
            .state
            .last_error = None;
    }

    pub fn record_pending_remote_revocation(
        &self,
        record: crate::RemoteSessionRecord,
        now: DateTime<Utc>,
    ) {
        self.inner
            .lock()
            .expect("mirror coordinator lock")
            .state
            .record_pending_remote_revocation(record, now);
    }

    pub fn record_pending_candidate_session(
        &self,
        record: crate::RemoteSessionRecord,
        now: DateTime<Utc>,
    ) {
        self.inner
            .lock()
            .expect("mirror coordinator lock")
            .state
            .record_pending_candidate_session(record, now);
    }

    pub fn should_notify(&self, error_is_persistent: bool) -> bool {
        let inner = self.inner.lock().expect("mirror coordinator lock");
        inner.state.has_any_reviews() || (error_is_persistent && inner.state.has_any_pair_error())
    }
}

pub struct SyncRun {
    coordinator: MirrorCoordinator,
    state: DesktopState,
    cycle_order: Vec<String>,
    active: bool,
    generation: u64,
}

/// Exclusive guard for lifecycle work that must not race a sync or setup.
pub struct LifecycleOperation {
    coordinator: MirrorCoordinator,
    active: bool,
}

impl LifecycleOperation {
    /// Publish an already-durable intermediate image without releasing the
    /// reservation, so a crash-recovery journal cannot be overwritten.
    pub fn publish_persisted_state(&mut self, state: DesktopState) -> Result<()> {
        if !self.active {
            return Err(DesktopError::InvalidState(
                "lifecycle operation is no longer active".to_string(),
            ));
        }
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        inner.state = state;
        inner.offline = false;
        Ok(())
    }

    pub fn finish_state(&mut self, state: DesktopState) {
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        inner.state = state;
        inner.offline = false;
        Self::release(&mut inner, &mut self.active);
    }

    pub fn finish_disconnect(&mut self) {
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        inner.state = inner.state.clone().into_disconnected(Utc::now());
        inner.offline = false;
        Self::release(&mut inner, &mut self.active);
    }

    fn release(inner: &mut CoordinatorInner, active: &mut bool) {
        if *active {
            inner.active_run = false;
            inner.active_sync_generation = None;
            inner.sync_cancellation = None;
            *active = false;
        }
    }
}

impl Drop for LifecycleOperation {
    fn drop(&mut self) {
        if self.active {
            let mut inner = self
                .coordinator
                .inner
                .lock()
                .expect("mirror coordinator lock");
            inner.active_run = false;
            inner.active_sync_generation = None;
            inner.sync_cancellation = None;
        }
    }
}

fn redact_error(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if lower.contains("authorization")
        || lower.contains("bearer ")
        || lower.contains("password")
        || lower.contains("totp")
        || lower.contains("cookie")
    {
        "The server rejected a protected request. Sign in again or check the server address."
            .to_string()
    } else {
        message.chars().take(240).collect()
    }
}

#[cfg(test)]
#[path = "coordinator_tests.rs"]
mod tests;

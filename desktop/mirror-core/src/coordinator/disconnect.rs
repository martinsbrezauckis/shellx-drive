use crate::{DesktopError, Result};

use super::{LifecycleOperation, MirrorCoordinator};

/// One generation-owned request to stop a live sync before Disconnect starts.
/// Dropping the request withdraws only this exact generation.
pub struct DisconnectRequest {
    coordinator: MirrorCoordinator,
    request_id: u64,
    active: bool,
}

impl MirrorCoordinator {
    pub fn request_disconnect(&self) -> Result<DisconnectRequest> {
        let mut inner = self.inner.lock().expect("mirror coordinator lock");
        if inner.disconnect_request.is_some() {
            return Err(DesktopError::InvalidState(
                "Disconnect is already waiting for synchronization to stop.".to_string(),
            ));
        }
        if inner.active_run && inner.active_sync_generation.is_none() {
            return Err(DesktopError::SyncAlreadyRunning);
        }
        inner.next_disconnect_request =
            inner
                .next_disconnect_request
                .checked_add(1)
                .ok_or_else(|| {
                    DesktopError::InvalidState(
                        "Disconnect request generation overflowed".to_string(),
                    )
                })?;
        let request_id = inner.next_disconnect_request;
        inner.disconnect_request = Some(request_id);
        if let Some(sync_generation) = inner.active_sync_generation {
            inner.sync_cancellation = Some((sync_generation, request_id));
        }
        Ok(DisconnectRequest {
            coordinator: self.clone(),
            request_id,
            active: true,
        })
    }
}

impl DisconnectRequest {
    /// Report whether the targeted sync has released its run guard. A pending
    /// request continues to block any replacement sync or lifecycle action.
    pub fn is_ready(&self) -> Result<bool> {
        let inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        if inner.disconnect_request != Some(self.request_id) {
            return Err(DesktopError::InvalidState(
                "Disconnect request ownership changed while waiting.".to_string(),
            ));
        }
        Ok(!inner.active_run)
    }

    /// Promote this exact request only after the sync guard released its last
    /// filesystem/network operation.
    pub fn try_begin(&mut self) -> Result<Option<LifecycleOperation>> {
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        if inner.disconnect_request != Some(self.request_id) {
            return Err(DesktopError::InvalidState(
                "Disconnect request ownership changed while waiting.".to_string(),
            ));
        }
        if inner.active_run {
            return Ok(None);
        }
        inner.active_run = true;
        inner.disconnect_request = None;
        inner.sync_cancellation = None;
        self.active = false;
        Ok(Some(LifecycleOperation {
            coordinator: self.coordinator.clone(),
            active: true,
        }))
    }
}

impl Drop for DisconnectRequest {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        if inner.disconnect_request == Some(self.request_id) {
            inner.disconnect_request = None;
        }
        if inner
            .sync_cancellation
            .is_some_and(|(_, request_id)| request_id == self.request_id)
        {
            inner.sync_cancellation = None;
        }
    }
}

//! Pair mutations guarded by the coordinator's global lifecycle lock.

use super::*;
use crate::SyncPair;

impl MirrorCoordinator {
    /// Adds and selects one empty-folder pair. The caller must already have
    /// checked the target root and placed credentials in the operating-system
    /// store for the shared server/account identity.
    pub fn configure_pair(&self, pair: SyncPair) -> Result<()> {
        let mut inner = self.inner.lock().expect("mirror coordinator lock");
        ensure_pair_mutation_allowed(&inner, "pairing")?;
        inner.state.configure_pair(pair)?;
        inner.offline = false;
        Ok(())
    }

    pub fn activate_pair(&self, pair_id: &str) -> Result<bool> {
        let mut inner = self.inner.lock().expect("mirror coordinator lock");
        ensure_pair_mutation_allowed(&inner, "location switching")?;
        let changed = inner.state.activate_pair(pair_id)?;
        inner.offline = false;
        Ok(changed)
    }
}

fn ensure_pair_mutation_allowed(inner: &CoordinatorInner, action: &str) -> Result<()> {
    if inner.active_run {
        return Err(DesktopError::SyncAlreadyRunning);
    }
    if inner.state.has_pending_disconnect_cleanup() {
        return Err(DesktopError::InvalidState(format!(
            "disconnect local cleanup is pending; {action} remains disabled"
        )));
    }
    Ok(())
}
